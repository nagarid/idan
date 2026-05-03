#!/bin/bash
# victim_csi.sh — Simulated Kubernetes Secrets Store CSI Driver (FUSE)
#
# Scenario:
#   A node-level CSI driver mounts a FUSE secrets volume into pods.
#   The daemon uses MD5(secret_value) as the FUSE nodeid — a content-addressed
#   design meant to deduplicate identical secrets across pods.
#
#   THE BUG: two secrets with the same value → same MD5 → same nodeid.
#   The kernel creates ONE shared VFS inode for both paths.
#   The last LOOKUP's mode bits win — unprivileged pod process can poison them.
#
# Run as root (simulates the node agent / CSI driver process):
#   sudo ./victim_csi.sh

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
MAG='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

MNTDIR="/tmp/k8s_secrets_mount"
POD_UID="a3f1c2d4-8b9e-4f7a-b2c1-d5e6f8901234"

info()  { echo -e "${GRN}[csi-driver]${NC} $*"; }
step()  { echo -e "${MAG}[setup]     ${NC} $*"; }
runcmd(){ echo -e "${CYN}[cmd]       ${BOLD}$1${NC}"; eval "$1"; }
warn()  { echo -e "${YEL}[warn]  $*${NC}"; }
err()   { echo -e "${RED}[error] $*${NC}"; }
sep()   { echo -e "${BLU}──────────────────────────────────────────────────${NC}"; }

# ── Checks ────────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]]              && { err "Run as root: ${BOLD}sudo ./victim_csi.sh${NC}"; exit 1; }
command -v python3 &>/dev/null || { err "python3 not found"; exit 1; }
[[ -e /dev/fuse ]]             || { err "/dev/fuse missing — run: sudo modprobe fuse"; exit 1; }

# ── Cleanup ───────────────────────────────────────────────────────────────────
DAEMON_PID=""
PYFILE=""
READY_FILE=""

cleanup() {
    echo
    sep
    step "Shutting down CSI driver..."
    [[ -n $DAEMON_PID ]] && {
        runcmd "kill $DAEMON_PID 2>/dev/null || true"
        wait "$DAEMON_PID" 2>/dev/null
    }
    runcmd "umount -l $MNTDIR 2>/dev/null || true"
    runcmd "rmdir  $MNTDIR    2>/dev/null || true"
    [[ -n $PYFILE     ]] && runcmd "rm -f $PYFILE"
    [[ -n $READY_FILE ]] && runcmd "rm -f $READY_FILE"
    step "Done."
}
trap cleanup EXIT SIGINT SIGTERM

# ── Header ────────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║    KUBERNETES SECRETS STORE CSI DRIVER  —  FUSE SIMULATION  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo
info  "Node:    $(hostname)"
info  "Kernel:  $(uname -r)"
info  "Pod UID: $POD_UID"
info  "Mount:   $MNTDIR"
echo
info  "Secrets served to this pod:"
echo -e "  ${GRN}dev-shared-key${NC}    nodeid=${BOLD}0x651b3722d014767b${NC}  mode=${BOLD}0644${NC}  (dev team readable)"
echo -e "  ${RED}prod-db-password${NC}  nodeid=${BOLD}0x651b3722d014767b${NC}  mode=${BOLD}0000${NC}  (app-sa only)"
echo
warn  "BUG: both secrets contain the same value."
warn  "     MD5(value) is used as nodeid for deduplication."
warn  "     Same value → same MD5 → same nodeid → ONE shared VFS inode."
warn  "     stat(dev-shared-key) poisons inode mode to 0644."
warn  "     open(prod-db-password) bypasses mode=0000 check."
echo

# ── Write Python CSI daemon ───────────────────────────────────────────────────
sep
PYFILE=$(mktemp /tmp/csi_daemon_XXXXXX.py)
READY_FILE=$(mktemp /tmp/csi_ready_XXXXXX)
step "Writing Python CSI FUSE daemon → $PYFILE"

cat > "$PYFILE" << 'PYEOF'
#!/usr/bin/env python3
"""
Simulated Kubernetes Secrets Store CSI driver (raw FUSE, no libfuse).

Nodeid design (the bug):
  nodeid = int.from_bytes(MD5(secret_value)[:8], 'little') & 0x7fffffffffffffff

Two secrets share value "ProdDevKey#7x9\n":
  dev-shared-key   → nodeid=0x651b3722d014767b  mode=0644
  prod-db-password → nodeid=0x651b3722d014767b  mode=0000  ← same nodeid!
"""
import os, sys, struct, ctypes, errno as E, hashlib

# ── FUSE opcodes ──────────────────────────────────────────────────────────────
FUSE_LOOKUP, FUSE_FORGET, FUSE_GETATTR    = 1, 2, 3
FUSE_OPEN,   FUSE_READ,   FUSE_STATFS     = 14, 15, 17
FUSE_RELEASE,FUSE_FSYNC,  FUSE_FLUSH      = 18, 20, 25
FUSE_INIT,   FUSE_OPENDIR                 = 26, 27
FUSE_READDIR,FUSE_RELEASEDIR              = 28, 29
FUSE_ACCESS, FUSE_BATCH_FORGET            = 34, 42

S_IFREG, S_IFDIR = 0o100000, 0o040000
DT_REG,  DT_DIR  = 8, 4

MNTDIR     = sys.argv[1]
READY_FILE = sys.argv[2]
ENTRY_TTL  = 3600          # 1-hour dentry cache — keeps the poison alive

BLU, YEL, RED, GRN, CYN, BOLD, NC = (
    '\033[0;34m', '\033[1;33m', '\033[0;31m',
    '\033[0;32m', '\033[0;36m', '\033[1m', '\033[0m')

def log(msg):
    print(f"{BLU}[csi-fuse]{NC} {msg}", file=sys.stderr, flush=True)

# ── Content-addressed nodeid (the buggy design) ───────────────────────────────

def content_nodeid(data: bytes) -> int:
    """MD5(content) truncated to 63-bit nodeid. Same value → same nodeid."""
    h = hashlib.md5(data).digest()
    return int.from_bytes(h[:8], 'little') & 0x7FFFFFFFFFFFFFFF

SHARED_VALUE   = b"ProdDevKey#7x9\n"
COLLIDING_NID  = content_nodeid(SHARED_VALUE)  # 0x651b3722d014767b

# Secrets catalog: name → (nodeid, mode, data)
SECRETS = {
    "dev-shared-key":   (COLLIDING_NID, S_IFREG | 0o644, SHARED_VALUE),
    "prod-db-password": (COLLIDING_NID, S_IFREG | 0o000, SHARED_VALUE),
}

log(f"Content-hash nodeid for shared value: {BOLD}0x{COLLIDING_NID:x}{NC}")
log(f"  dev-shared-key   → nodeid={BOLD}0x{COLLIDING_NID:x}{NC}  mode={GRN}0644{NC}")
log(f"  prod-db-password → nodeid={BOLD}0x{COLLIDING_NID:x}{NC}  mode={RED}0000{NC}  ← collision!")

# ── FUSE struct layouts ───────────────────────────────────────────────────────
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
    return ATTR.pack(ino, size, 0, 0,0,0, 0,0,0, mode, nlink, 0,0,0, 4096,0)

def reply_ok(fd, uniq, body=b''):
    os.write(fd, OUT_H.pack(16 + len(body), 0, uniq) + body)

def reply_err(fd, uniq, e):
    os.write(fd, OUT_H.pack(16, -e, uniq))

# ── Handlers ──────────────────────────────────────────────────────────────────

def on_init(fd, uniq, _body):
    reply_ok(fd, uniq, IOUT.pack(7, 39, 65536, 0, 0,0, 65536,0, 0,0))
    log(f"FUSE_INIT complete — secrets volume ready at {BOLD}{MNTDIR}{NC}")

def on_getattr(fd, uniq, nid):
    if nid == 1:
        a = make_attr(1, S_IFDIR | 0o755, nlink=2)
    elif nid == COLLIDING_NID:
        # The daemon can't tell which file is being asked about — both share
        # the same nodeid. Return the restrictive mode so GETATTR doesn't
        # accidentally grant access via a stale refresh.
        a = make_attr(nid, S_IFREG | 0o000, size=len(SHARED_VALUE))
    else:
        a = make_attr(nid, S_IFREG | 0o644, size=0)
    reply_ok(fd, uniq, AOUT.pack(ENTRY_TTL, 0, 0) + a)

def on_lookup(fd, uniq, name):
    if name not in SECRETS:
        reply_err(fd, uniq, E.ENOENT)
        return
    nid, mode, data = SECRETS[name]
    mode_str = f"{mode & 0o777:04o}"
    color = GRN if (mode & 0o444) else RED
    log(f"LOOKUP '{CYN}{name}{NC}' → nodeid={BOLD}0x{nid:x}{NC}  mode={color}{mode_str}{NC}")
    a = make_attr(nid, mode, size=len(data))
    reply_ok(fd, uniq, EOUT.pack(nid, 1, ENTRY_TTL, ENTRY_TTL, 0, 0) + a)

def on_open(fd, uniq, nid):
    reply_ok(fd, uniq, OOUT.pack(nid & 0xFFFF, 0, 0))
    log(f"OPEN  nodeid=0x{nid:x}")

def on_read(fd, uniq, nid, body):
    _fh, offset, size = RIN.unpack_from(body)[:3]
    log(f"READ  nodeid=0x{nid:x}  offset={offset}  size={size}")
    reply_ok(fd, uniq, SHARED_VALUE[offset:offset+size])

def on_readdir(fd, uniq, _nid, body):
    _fh, offset, size = RIN.unpack_from(body)[:3]
    if offset > 0:
        reply_ok(fd, uniq, b'')
        return
    entries = [
        (1,            '.',              DT_DIR),
        (1,            '..',             DT_DIR),
    ]
    for name, (nid, _mode, _data) in SECRETS.items():
        entries.append((nid, name, DT_REG))
    buf, cur_off = b'', 0
    for ino, name, dtype in entries:
        nb    = name.encode()
        recsz = (DIRH.size + len(nb) + 7) & ~7
        cur_off += recsz
        rec   = DIRH.pack(ino, cur_off, len(nb), dtype) + nb
        rec  += b'\x00' * (recsz - len(rec))
        buf  += rec
    reply_ok(fd, uniq, buf[:size])

def on_statfs(fd, uniq):
    reply_ok(fd, uniq,
             SFST.pack(1000,500,500,100,100, 4096,255,4096,0, 0,0,0,0,0,0))

# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    ffd = os.open("/dev/fuse", os.O_RDWR | os.O_CLOEXEC)

    libc = ctypes.CDLL(None, use_errno=True)
    opts = (f"fd={ffd},rootmode=40755,user_id=0,group_id=0"
            f",allow_other,default_permissions").encode()
    if libc.mount(b"k8s-secrets-csi", MNTDIR.encode(), b"fuse", 0, opts) != 0:
        print(f"mount() failed: {os.strerror(ctypes.get_errno())}", file=sys.stderr)
        sys.exit(1)

    log(f"Secrets volume mounted at {BOLD}{MNTDIR}{NC}")
    log(f"Mount options: allow_other + default_permissions (kernel enforces inode modes)")
    log(f"Dentry TTL: {ENTRY_TTL}s — poisoned inode stays cached for 1 hour")
    log(f"Waiting for requests from pods...")

    open(READY_FILE, 'w').close()

    NO_REPLY = {FUSE_FORGET, FUSE_BATCH_FORGET}

    while True:
        try:
            msg = os.read(ffd, 1 << 17)
        except OSError:
            break
        if not msg:
            break

        hdr  = IN_H.unpack_from(msg)
        _len, op, uniq, nid = hdr[0], hdr[1], hdr[2], hdr[3]
        body = msg[IN_H.size:]
        name = body.split(b'\x00')[0].decode(errors='replace')

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

step "Python CSI daemon written ($(wc -l < "$PYFILE") lines)"

# ── Create mount dir ──────────────────────────────────────────────────────────
sep
step "Creating secrets volume mount point"
runcmd "mkdir -p $MNTDIR && chmod 755 $MNTDIR"

# ── Start daemon ──────────────────────────────────────────────────────────────
sep
step "Starting CSI FUSE daemon in background..."
echo -e "${CYN}[cmd]       ${BOLD}python3 $PYFILE $MNTDIR $READY_FILE &${NC}"
python3 "$PYFILE" "$MNTDIR" "$READY_FILE" &
DAEMON_PID=$!

step "Waiting for daemon to mount secrets volume..."
for i in $(seq 1 20); do
    sleep 0.2
    [[ -f $READY_FILE ]] && break
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        err "Daemon exited before mounting"
        exit 1
    fi
done

if ! grep -q "k8s_secrets_mount" /proc/mounts; then
    err "Mount did not appear in /proc/mounts"
    exit 1
fi

# ── Ready ─────────────────────────────────────────────────────────────────────
sep
echo
echo -e "${BOLD}${GRN}✓ Secrets volume mounted and ready${NC}"
echo
runcmd "grep k8s_secrets_mount /proc/mounts"
echo
runcmd "ls -la $MNTDIR"
echo
step "Flushing dentry cache (simulates pod startup with no prior state)..."
runcmd "echo 2 > /proc/sys/vm/drop_caches"
echo
info  "Pod UID:  ${BOLD}$POD_UID${NC}"
info  "Secrets available inside the pod at:  ${CYN}${BOLD}$MNTDIR/${NC}"
echo
info  "Run the attacker (pod process) in another terminal:"
echo -e "  ${CYN}${BOLD}gcc -O2 -o /tmp/attacker_pod /path/to/attacker_pod.c && /tmp/attacker_pod${NC}"
echo
sep
echo -e "${YEL}Press Ctrl+C to unmount and stop the daemon${NC}"
echo

wait "$DAEMON_PID"
