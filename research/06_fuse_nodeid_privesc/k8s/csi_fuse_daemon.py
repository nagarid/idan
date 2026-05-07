#!/usr/bin/env python3
"""
Buggy Kubernetes Secrets Store CSI FUSE daemon.

Nodeid design flaw:
  nodeid = int.from_bytes(MD5(secret_value)[:8], 'little') & 0x7fffffffffffffff

Two secrets with the same value produce the same MD5 → same nodeid → one shared
VFS inode. The last FUSE_LOOKUP's mode wins. An unprivileged pod can poison the
inode mode from 0000 to 0644 with a single stat() of a world-readable secret.

Usage: python3 csi_fuse_daemon.py <mountpoint>
"""
import os, sys, struct, ctypes, errno as E, hashlib, signal

FUSE_LOOKUP, FUSE_FORGET, FUSE_GETATTR = 1, 2, 3
FUSE_OPEN,   FUSE_READ,   FUSE_STATFS  = 14, 15, 17
FUSE_RELEASE,FUSE_FLUSH,  FUSE_INIT    = 18, 25, 26
FUSE_OPENDIR,FUSE_READDIR              = 27, 28
FUSE_RELEASEDIR, FUSE_ACCESS           = 29, 34
FUSE_BATCH_FORGET                      = 42
S_IFREG, S_IFDIR                       = 0o100000, 0o040000
DT_REG,  DT_DIR                        = 8, 4

MNTDIR    = sys.argv[1] if len(sys.argv) > 1 else "/var/lib/csi-demo-secrets"
ENTRY_TTL = 3600   # 1-hour dentry cache — keeps the poison alive

R = '\033[0;31m'; G = '\033[0;32m'; Y = '\033[1;33m'
B = '\033[0;34m'; C = '\033[0;36m'; BOLD = '\033[1m'; NC = '\033[0m'

def log(msg, file=sys.stderr):
    print(f"{B}[csi-fuse]{NC} {msg}", file=file, flush=True)

def content_nodeid(data: bytes) -> int:
    """MD5(content) truncated to 63-bit nodeid. Same value → same nodeid."""
    return int.from_bytes(hashlib.md5(data).digest()[:8], 'little') & 0x7FFFFFFFFFFFFFFF

# Both secrets share this value — realistic: developer reused a test credential.
SHARED_VALUE  = b"ProdDevKey#7x9\n"
COLLIDING_NID = content_nodeid(SHARED_VALUE)

# Secrets table: name → (nodeid, mode, content)
SECRETS = {
    "dev-shared-key":   (COLLIDING_NID, S_IFREG | 0o644, SHARED_VALUE),
    "prod-db-password": (COLLIDING_NID, S_IFREG | 0o000, SHARED_VALUE),
}

log(f"CSI driver starting — content-addressed nodeid design")
log(f"MD5({repr(SHARED_VALUE.decode())[1:-1]})[:8] = {BOLD}0x{COLLIDING_NID:016x}{NC}")
log(f"  dev-shared-key   → nodeid 0x{COLLIDING_NID:x}  mode={G}0644{NC}  (dev-sa readable)")
log(f"  prod-db-password → nodeid 0x{COLLIDING_NID:x}  mode={R}0000{NC}  (app-sa only) ← COLLISION!")

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
    return ATTR.pack(ino, size, 0,0,0,0, 0,0,0, mode, nlink, 0,0,0, 4096, 0)

def reply_ok(fd, uniq, body=b''):
    os.write(fd, OUT_H.pack(OUT_H.size + len(body), 0, uniq) + body)

def reply_err(fd, uniq, e):
    os.write(fd, OUT_H.pack(OUT_H.size, -e, uniq))

def on_init(fd, uniq, _b):
    reply_ok(fd, uniq, IOUT.pack(7, 39, 65536, 0, 0, 0, 65536, 0, 0, 0))
    log(f"FUSE_INIT — secrets volume ready at {BOLD}{MNTDIR}{NC}")

def on_getattr(fd, uniq, nid):
    if nid == 1:
        a = make_attr(1, S_IFDIR | 0o755, nlink=2)
    elif nid == COLLIDING_NID:
        # Return restrictive mode on GETATTR — daemon can't tell which path
        a = make_attr(nid, S_IFREG | 0o000, size=len(SHARED_VALUE))
    else:
        a = make_attr(nid, S_IFREG | 0o644, size=0)
    reply_ok(fd, uniq, AOUT.pack(ENTRY_TTL, 0, 0) + a)

def on_lookup(fd, uniq, name):
    if name not in SECRETS:
        reply_err(fd, uniq, E.ENOENT)
        return
    nid, mode, data = SECRETS[name]
    perm  = mode & 0o777
    color = G if (mode & 0o444) else R
    log(f"FUSE_LOOKUP  {C}'{name}'{NC} → nodeid {BOLD}0x{nid:x}{NC}  mode={color}0{perm:04o}{NC}  ttl={ENTRY_TTL}s")
    reply_ok(fd, uniq, EOUT.pack(nid, 1, ENTRY_TTL, ENTRY_TTL, 0, 0) + make_attr(nid, mode, size=len(data)))

def on_open(fd, uniq, nid):
    reply_ok(fd, uniq, OOUT.pack(nid, 0, 0))

def on_read(fd, uniq, nid, body):
    _fh, offset, size = RIN.unpack_from(body)[:3]
    reply_ok(fd, uniq, SHARED_VALUE[offset:offset+size])

def on_readdir(fd, uniq, _nid, body):
    _fh, offset, size = RIN.unpack_from(body)[:3]
    if offset > 0:
        reply_ok(fd, uniq, b'')
        return
    entries = [(1,'.',DT_DIR),(1,'..',DT_DIR)] + \
              [(nid, n, DT_REG) for n,(nid,_m,_d) in SECRETS.items()]
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
    os.makedirs(MNTDIR, exist_ok=True)
    ffd = os.open("/dev/fuse", os.O_RDWR | os.O_CLOEXEC)

    libc = ctypes.CDLL(None, use_errno=True)
    opts = (f"fd={ffd},rootmode=40755,user_id=0,group_id=0"
            f",allow_other,default_permissions").encode()
    if libc.mount(b"csi-secrets", MNTDIR.encode(), b"fuse", 0, opts) != 0:
        log(f"mount() failed: {os.strerror(ctypes.get_errno())}")
        sys.exit(1)

    log(f"Mounted at {BOLD}{MNTDIR}{NC}  (allow_other + default_permissions)")
    log(f"Dentry TTL {ENTRY_TTL}s — poisoned inode survives for 1 hour")

    # Signal readiness to orchestration script
    ready = os.environ.get("READY_FILE", "")
    if ready:
        open(ready, 'w').close()

    NO_REPLY = {FUSE_FORGET, FUSE_BATCH_FORGET}
    while True:
        try:
            msg = os.read(ffd, 1 << 17)
        except OSError:
            break
        if not msg:
            break
        hdr  = IN_H.unpack_from(msg)
        op, uniq, nid = hdr[1], hdr[2], hdr[3]
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
