/*
 * fuse_poc.c — FUSE + io_uring attack surface PoC
 *
 * Unprivileged access: unshare(CLONE_NEWUSER|CLONE_NEWNS)
 * → CAP_SYS_ADMIN in isolated namespace → FUSE mount via /dev/fuse
 *
 * Tests:
 *   1. Minimal FUSE daemon (raw protocol) — establish baseline
 *   2. FUSE passthrough IOCTLs (FUSE_DEV_IOC_BACKING_OPEN/CLOSE)
 *   3. TOCTOU race — delayed FUSE response window
 *   4. Nodeid aliasing — two paths same nodeid
 *   5. FUSE + io_uring request/response probe
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <pthread.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/fuse.h>

/* ─── FUSE passthrough ioctls (kernel 6.5+, not in 7.39 headers) ─────────── */
struct fuse_backing_map { __s32 fd; __u32 flags; __u64 padding; };
#define FUSE_DEV_IOC_MAGIC       229
#define FUSE_DEV_IOC_BACKING_OPEN  _IOW(FUSE_DEV_IOC_MAGIC, 1, struct fuse_backing_map)
#define FUSE_DEV_IOC_BACKING_CLOSE _IOW(FUSE_DEV_IOC_MAGIC, 2, uint32_t)
#define FOPEN_PASSTHROUGH        (1u << 3)

/* io_uring FUSE ioctl (CONFIG_FUSE_IO_URING, kernel 6.10+) */
#define FUSE_DEV_IOC_URING_CMD   _IOWR(FUSE_DEV_IOC_MAGIC, 3, uint32_t)

/* ─── FUSE protocol helpers ──────────────────────────────────────────────── */

static int fuse_fd = -1;
static char mntdir[64];

/* send a FUSE reply */
static void fuse_reply(uint64_t unique, int32_t err,
                       const void *body, size_t blen) {
    struct fuse_out_header hdr = {
        .len    = sizeof(hdr) + (uint32_t)blen,
        .error  = err,
        .unique = unique,
    };
    struct iovec iov[2] = {
        { .iov_base = &hdr,         .iov_len = sizeof(hdr) },
        { .iov_base = (void *)body, .iov_len = blen         },
    };
    writev(fuse_fd, iov, body ? 2 : 1);
}

#define FUSE_REPLY_ERR(uniq, e)  fuse_reply((uniq), -(e), NULL, 0)
#define FUSE_REPLY_OK(uniq, b)   fuse_reply((uniq), 0, &(b), sizeof(b))

/* ─── State for delay-based TOCTOU test ─────────────────────────────────── */

static volatile int toctou_delay_ms = 0;  /* injected delay in FUSE_LOOKUP */
static volatile int toctou_flip     = 0;  /* 1 → after lookup, swap symlink */

/* ─── Minimal FUSE daemon ────────────────────────────────────────────────── */

#define ROOT_INO  1
#define FILE1_INO 2
#define FILE2_INO 3
#define LINK_INO  4

static struct fuse_entry_out make_entry(uint64_t ino, uint32_t mode) {
    struct fuse_entry_out e = {0};
    e.nodeid           = ino;
    e.generation       = 1;
    e.entry_valid      = 0;
    e.attr_valid       = 0;
    e.attr.ino         = ino;
    e.attr.mode        = mode;
    e.attr.nlink       = 1;
    e.attr.uid         = 0;
    e.attr.gid         = 0;
    e.attr.size        = ino == FILE1_INO ? 64 : 0;
    return e;
}

static void handle_init(uint64_t unique, struct fuse_init_in *ini) {
    struct fuse_init_out out = {0};
    out.major         = FUSE_KERNEL_VERSION;
    out.minor         = FUSE_KERNEL_MINOR_VERSION;
    out.max_readahead = ini->max_readahead;
    out.flags         = 0;
    out.max_write     = 65536;
    fuse_reply(unique, 0, &out, sizeof(out));
}

static void handle_getattr(uint64_t unique, uint64_t nodeid) {
    struct fuse_attr_out out = {0};
    out.attr.ino   = nodeid;
    out.attr.nlink = 1;
    out.attr.uid   = 0;
    out.attr.gid   = 0;
    switch (nodeid) {
    case ROOT_INO:
        out.attr.mode = S_IFDIR | 0755;
        out.attr.size = 0;
        break;
    case FILE1_INO:
        out.attr.mode = S_IFREG | 0644;
        out.attr.size = 64;
        break;
    case FILE2_INO:
        out.attr.mode = S_IFREG | 0644;
        out.attr.size = 64;
        break;
    case LINK_INO:
        out.attr.mode = S_IFLNK | 0777;
        out.attr.size = 5; /* "file1" */
        break;
    default:
        FUSE_REPLY_ERR(unique, ENOENT);
        return;
    }
    fuse_reply(unique, 0, &out, sizeof(out));
}

static void handle_lookup(uint64_t unique, const char *name) {
    /* Inject delay for TOCTOU test */
    if (toctou_delay_ms > 0) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = toctou_delay_ms * 1000000L };
        nanosleep(&ts, NULL);
        toctou_flip = 1; /* signal: delay has started, race window open */
    }

    struct fuse_entry_out e = {0};
    if (!strcmp(name, "file1")) {
        e = make_entry(FILE1_INO, S_IFREG | 0644);
    } else if (!strcmp(name, "file2")) {
        e = make_entry(FILE2_INO, S_IFREG | 0644);
    } else if (!strcmp(name, "link")) {
        e = make_entry(LINK_INO, S_IFLNK | 0777);
    } else if (!strcmp(name, "alias")) {
        /* aliased nodeid: returns FILE1_INO for a different path name */
        e = make_entry(FILE1_INO, S_IFREG | 0644);
    } else {
        FUSE_REPLY_ERR(unique, ENOENT);
        return;
    }
    fuse_reply(unique, 0, &e, sizeof(e));
}

static void handle_open(uint64_t unique, uint64_t nodeid) {
    struct fuse_open_out out = {0};
    out.fh       = nodeid * 100;
    out.open_flags = 0;
    fuse_reply(unique, 0, &out, sizeof(out));
}

static void handle_read(uint64_t unique, uint64_t fh) {
    (void)fh;
    char buf[64];
    memset(buf, 'A', sizeof(buf));
    memcpy(buf, "FUSE_DATA:", 10);
    fuse_reply(unique, 0, buf, sizeof(buf));
}

static void handle_readlink(uint64_t unique, uint64_t nodeid) {
    if (nodeid != LINK_INO) { FUSE_REPLY_ERR(unique, EINVAL); return; }
    const char *target = "file1";
    fuse_reply(unique, 0, target, strlen(target));
}

static void handle_release(uint64_t unique) {
    struct fuse_release_in dummy = {0};
    (void)dummy;
    FUSE_REPLY_ERR(unique, 0);
}

static void *fuse_daemon(void *arg) {
    (void)arg;
    char buf[1 << 17]; /* 128KB — above FUSE_MIN_READ_BUFFER */

    while (1) {
        ssize_t n = read(fuse_fd, buf, sizeof(buf));
        if (n <= 0) break;

        struct fuse_in_header *hdr = (struct fuse_in_header *)buf;
        char *body = buf + sizeof(*hdr);

        switch (hdr->opcode) {
        case FUSE_INIT:
            handle_init(hdr->unique, (struct fuse_init_in *)body);
            break;
        case FUSE_GETATTR:
            handle_getattr(hdr->unique, hdr->nodeid);
            break;
        case FUSE_LOOKUP:
            handle_lookup(hdr->unique, body);
            break;
        case FUSE_OPENDIR:
        case FUSE_OPEN:
            handle_open(hdr->unique, hdr->nodeid);
            break;
        case FUSE_READ:
        case FUSE_READDIR:
            handle_read(hdr->unique, ((struct fuse_read_in *)body)->fh);
            break;
        case FUSE_READLINK:
            handle_readlink(hdr->unique, hdr->nodeid);
            break;
        case FUSE_RELEASEDIR:
        case FUSE_RELEASE:
            handle_release(hdr->unique);
            break;
        case FUSE_FORGET:
        case FUSE_BATCH_FORGET:
            /* no reply expected */
            break;
        case FUSE_STATFS: {
            struct fuse_statfs_out s = {0};
            s.st.blocks = 1000; s.st.bfree = 500;
            s.st.namelen = 255; s.st.bsize = 4096;
            fuse_reply(hdr->unique, 0, &s, sizeof(s));
            break;
        }
        case FUSE_SETATTR: {
            handle_getattr(hdr->unique, hdr->nodeid);
            break;
        }
        default:
            FUSE_REPLY_ERR(hdr->unique, ENOSYS);
            break;
        }
    }
    return NULL;
}

/* ─── Namespace + mount setup ────────────────────────────────────────────── */

static int setup_ns_and_mount(void) {
    /* Save real uid/gid BEFORE entering the new user namespace.
     * After unshare(NEWUSER), getuid() returns 65534 (overflow) until
     * uid_map is written. We need the host-side uid for the map entry. */
    uid_t ruid = getuid();
    gid_t rgid = getgid();
    char map[64];
    int f;

    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
        perror("[!] unshare(NEWUSER|NEWNS)");
        return -1;
    }

    /* Write uid_map: map our real uid → 0 inside namespace */
    f = open("/proc/self/setgroups", O_WRONLY);
    if (f >= 0) { (void)write(f, "deny", 4); close(f); }

    snprintf(map, sizeof(map), "0 %d 1\n", (int)ruid);
    f = open("/proc/self/uid_map", O_WRONLY);
    if (f >= 0) { (void)write(f, map, strlen(map)); close(f); }
    else { perror("uid_map"); }

    snprintf(map, sizeof(map), "0 %d 1\n", (int)rgid);
    f = open("/proc/self/gid_map", O_WRONLY);
    if (f >= 0) { (void)write(f, map, strlen(map)); close(f); }

    /* open /dev/fuse */
    fuse_fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (fuse_fd < 0) { perror("[!] open /dev/fuse"); return -1; }

    /* create mount point */
    snprintf(mntdir, sizeof(mntdir), "/tmp/fuse_poc_mnt_%d", getpid());
    mkdir(mntdir, 0755);

    char opts[128];
    snprintf(opts, sizeof(opts),
             "fd=%d,rootmode=40755,user_id=0,group_id=0", fuse_fd);

    if (mount("fuse_poc", mntdir, "fuse", 0, opts) < 0) {
        perror("[!] mount fuse");
        return -1;
    }

    printf("[+] FUSE mounted at %s (fd=%d)\n", mntdir, fuse_fd);
    return 0;
}

/* ─── TEST 1: baseline FUSE ops ─────────────────────────────────────────── */

static void test_basic_ops(void) {
    printf("\n[TEST 1] basic FUSE operations\n");
    char path[128];

    snprintf(path, sizeof(path), "%s/file1", mntdir);
    struct stat st;
    int r = stat(path, &st);
    printf("  stat file1: %s size=%lld\n",
           r ? strerror(errno) : "OK", r ? 0LL : (long long)st.st_size);

    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char buf[64]; ssize_t n = read(fd, buf, sizeof(buf));
        printf("  read file1: %zd bytes: %.10s...\n", n, n > 0 ? buf : "");
        close(fd);
    } else {
        printf("  open file1: %s\n", strerror(errno));
    }

    snprintf(path, sizeof(path), "%s/link", mntdir);
    char lbuf[64];
    ssize_t ln = readlink(path, lbuf, sizeof(lbuf) - 1);
    if (ln >= 0) { lbuf[ln] = 0; printf("  readlink link→%s\n", lbuf); }

    printf("  [!] check dmesg for anomalies\n");
}

/* ─── TEST 2: passthrough IOCTLs ─────────────────────────────────────────── */

static void test_passthrough_ioctl(void) {
    printf("\n[TEST 2] FUSE passthrough ioctl probe\n");

    /* FUSE_DEV_IOC_BACKING_OPEN: associate a real fd as backing */
    int target_fd = open("/etc/hostname", O_RDONLY);
    if (target_fd < 0) { perror("  open /etc/hostname"); return; }

    struct fuse_backing_map bmap = { .fd = target_fd, .flags = 0, .padding = 0 };
    int r = ioctl(fuse_fd, FUSE_DEV_IOC_BACKING_OPEN, &bmap);
    printf("  FUSE_DEV_IOC_BACKING_OPEN(/etc/hostname): r=%d errno=%d (%s)\n",
           r, errno, strerror(errno));

    if (r >= 0) {
        /* backing_id = r, try to close it */
        uint32_t backing_id = (uint32_t)r;
        int rc = ioctl(fuse_fd, FUSE_DEV_IOC_BACKING_CLOSE, &backing_id);
        printf("  FUSE_DEV_IOC_BACKING_CLOSE(id=%u): r=%d errno=%d (%s)\n",
               backing_id, rc, errno, strerror(errno));
    }

    /* Try with invalid fd */
    bmap.fd = 999;
    r = ioctl(fuse_fd, FUSE_DEV_IOC_BACKING_OPEN, &bmap);
    printf("  FUSE_DEV_IOC_BACKING_OPEN(invalid_fd): r=%d errno=%d (%s)\n",
           r, errno, strerror(errno));

    /* Try double-close */
    uint32_t bad_id = 0xdeadbeef;
    r = ioctl(fuse_fd, FUSE_DEV_IOC_BACKING_CLOSE, &bad_id);
    printf("  FUSE_DEV_IOC_BACKING_CLOSE(bad_id=0xdeadbeef): r=%d errno=%d (%s)\n",
           r, errno, strerror(errno));

    /* Probe FUSE_DEV_IOC_URING_CMD (CONFIG_FUSE_IO_URING) */
    uint32_t uring_arg = 0;
    r = ioctl(fuse_fd, FUSE_DEV_IOC_URING_CMD, &uring_arg);
    printf("  FUSE_DEV_IOC_URING_CMD probe: r=%d errno=%d (%s)\n",
           r, errno, strerror(errno));

    close(target_fd);
    printf("  [!] check dmesg for anomalies\n");
}

/* ─── TEST 3: TOCTOU race window ─────────────────────────────────────────── */

static volatile int toctou_result = 0;
static char toctou_victim_path[128];

static void *toctou_racer(void *arg) {
    (void)arg;
    /* Wait for the lookup delay to start (race window open) */
    while (!toctou_flip)
        sched_yield();

    /* Replace the file with a symlink to something else while kernel
     * is waiting for FUSE_LOOKUP response — TOCTOU race window */
    unlink(toctou_victim_path);
    /* In a real attack: symlink to /etc/shadow */
    /* Here: demonstrate the race timing only */
    toctou_result = 1;
    return NULL;
}

static void test_toctou(void) {
    printf("\n[TEST 3] TOCTOU race via FUSE response delay\n");

    snprintf(toctou_victim_path, sizeof(toctou_victim_path),
             "%s/file1", mntdir);

    /* Enable 50ms delay in FUSE_LOOKUP responses */
    toctou_flip     = 0;
    toctou_delay_ms = 50;

    pthread_t racer;
    pthread_create(&racer, NULL, toctou_racer, NULL);

    /* stat will trigger FUSE_LOOKUP → 50ms delay → race window */
    struct stat st;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    stat(toctou_victim_path, &st);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    pthread_join(racer, NULL);
    toctou_delay_ms = 0;
    toctou_flip     = 0;

    long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000 +
                      (t1.tv_nsec - t0.tv_nsec) / 1000000;
    printf("  FUSE_LOOKUP with 50ms delay: %ldms (race window=%ldms)\n",
           elapsed_ms, elapsed_ms);
    printf("  race thread fired: %s\n", toctou_result ? "YES" : "no");
    printf("  [!] Real attack: race setuid binary's access()+open() via delay\n");
}

/* ─── TEST 4: nodeid aliasing ────────────────────────────────────────────── */

static void test_nodeid_alias(void) {
    printf("\n[TEST 4] FUSE nodeid aliasing — two paths, same inode\n");

    char p1[128], p2[128];
    snprintf(p1, sizeof(p1), "%s/file1", mntdir);
    snprintf(p2, sizeof(p2), "%s/alias", mntdir); /* alias also returns FILE1_INO */

    struct stat s1 = {0}, s2 = {0};
    stat(p1, &s1);
    stat(p2, &s2);

    printf("  file1 ino=%lu  alias ino=%lu  match=%s\n",
           (unsigned long)s1.st_ino, (unsigned long)s2.st_ino,
           s1.st_ino == s2.st_ino ? "YES (ALIAS)" : "no");

    if (s1.st_ino == s2.st_ino)
        printf("  [!] VFS inode cache entries collide — dentry confusion possible\n");

    printf("  [!] check dmesg for BUG/WARNING\n");
}

/* ─── TEST 5: rapid mount/unmount stress ─────────────────────────────────── */

static void test_mount_stress(void) {
    printf("\n[TEST 5] rapid stat/open stress on FUSE filesystem\n");
    char path[128];
    int ok = 0, err = 0;
    for (int i = 0; i < 500; i++) {
        snprintf(path, sizeof(path), "%s/%s",
                 mntdir, (i % 3 == 0) ? "file1" : (i % 3 == 1) ? "file2" : "noexist");
        struct stat st;
        if (stat(path, &st) == 0) ok++;
        else err++;
    }
    printf("  500 stat ops: %d ok, %d ENOENT\n", ok, err);
    printf("  [!] check dmesg for KASAN/KFENCE\n");
}

/* ─── main ───────────────────────────────────────────────────────────────── */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0); /* unbuffered for redirected output */
    printf("=== FUSE + io_uring Attack Surface PoC ===\n");
    printf("=== Kernel 6.18.5 | Ubuntu 24.04        ===\n\n");

    if (setup_ns_and_mount() < 0) return 1;

    pthread_t daemon_tid;
    pthread_create(&daemon_tid, NULL, fuse_daemon, NULL);

    /* Give daemon time to handle FUSE_INIT */
    usleep(100000);

    test_basic_ops();
    test_passthrough_ioctl();
    test_toctou();
    test_nodeid_alias();
    test_mount_stress();

    printf("\n[SUMMARY]\n");
    printf("  dmesg | grep -E 'BUG:|KASAN|KFENCE|WARNING:'  — kernel anomalies\n");
    printf("  grep -r PASSTHROUGH /proc/sys/fs/fuse/ 2>/dev/null\n");

    /* Unmount and cleanup */
    umount2(mntdir, MNT_DETACH);
    close(fuse_fd);  /* signals daemon thread to exit */
    pthread_join(daemon_tid, NULL);
    rmdir(mntdir);
    return 0;
}
