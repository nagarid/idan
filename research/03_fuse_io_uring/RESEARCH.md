# FUSE + io_uring Attack Surface Research
## Kernel: 6.18.5 | Ubuntu 24.04

## Kernel Config
```
CONFIG_FUSE_FS=y
CONFIG_FUSE_PASSTHROUGH=y   ← FUSE passthrough (backing file support)
CONFIG_FUSE_IO_URING=y      ← FUSE requests via io_uring rings
```

## Unprivileged Access Path
`unshare --user --map-root-user --mount` → CAP_SYS_ADMIN in isolated
user+mount namespace → full FUSE mount control via /dev/fuse (world-writable).

## FUSE Protocol (kernel 7.39 / 6.18.5)

```
User daemon (/dev/fuse)
     │
     ├─ read()  → receives struct fuse_in_header + opcode-specific body
     │             opcodes: FUSE_LOOKUP=1, FUSE_GETATTR=3, FUSE_OPEN=14,
     │                      FUSE_READ=15, FUSE_WRITE=16, FUSE_INIT=26, ...
     │
     └─ write() → sends struct fuse_out_header + reply body
```

io_uring FUSE variant (CONFIG_FUSE_IO_URING=y):
- Daemon registers io_uring instance with /dev/fuse via ioctl
- Kernel posts FUSE requests to io_uring SQ (kernel→userspace writes)
- Daemon completes via io_uring CQ (userspace→kernel writes)
- New memory model: shared ring between kernel FS layer and daemon

## High-Value Attack Surfaces

### 1. FUSE TOCTOU — classic bypass
FUSE daemon controls filesystem response timing.
By sleeping between `stat()/access()` check and `open()`, attacker can
win the race window in setuid-aware code:
```
thread1: access("/fuse/tmpfile")  → daemon returns "allowed"
thread2: rename("/etc/shadow", "/fuse/tmpfile")
thread1: open("/fuse/tmpfile")    → now opens /etc/shadow
```
Attack requires setuid binary that does two-step access-then-open with
an untrusted path. `pkexec`, `sudo`, `newgrp` historically vulnerable.

### 2. FUSE Passthrough — backing file substitution
`CONFIG_FUSE_PASSTHROUGH=y` allows attaching a real fd to a FUSE file
via `FUSE_DEV_IOC_BACKING_OPEN` ioctl on /dev/fuse.

When FUSE_OPEN returns `FOPEN_PASSTHROUGH` flag in open reply, subsequent
read/write go directly to the backing fd, bypassing the FUSE daemon.

Attack vector:
- Associate backing fd to a sensitive file (e.g., /etc/passwd read fd)
- Expose the FUSE file via a path reachable by a privileged process
- Privileged process opens FUSE file, reads from backing fd
- If backing fd refcount is raced during FUSE_OPEN → passthrough setup:
  possible UAF of file* in the passthrough path

Relevant ioctls:
```c
#define FUSE_DEV_IOC_MAGIC 229
#define FUSE_DEV_IOC_BACKING_OPEN  _IOW(229, 1, struct fuse_backing_map)
#define FUSE_DEV_IOC_BACKING_CLOSE _IOW(229, 2, uint32_t)
struct fuse_backing_map { __s32 fd; __u32 flags; __u64 padding; };
```

### 3. FUSE + io_uring — shared ring memory races
When daemon uses io_uring for FUSE request handling (requires opt-in),
the kernel writes request data into io_uring-accessible memory. Attack:

a) **Ring teardown race**: io_uring fd is closed while in-flight FUSE
   request references shared ring memory → UAF in io_uring context
b) **CQE injection**: Daemon crafts malformed CQE (completion) data;
   kernel interprets response body as trusted (from daemon perspective)
   but the response memory is writable by attacker
c) **Multiple completions**: Submit multiple CQEs for same unique ID →
   FUSE may process first, then second overwrites freed request

### 4. FUSE GETATTR / LOOKUP ID aliasing
fuse_inode has a nodeid. If daemon returns the same nodeid for two
different paths, kernel VFS layer may confuse them. Combined with dentry
cache invalidation, this can produce stale dentries pointing to wrong inodes.

## Test Results (fuse_poc.c, kernel 6.18.5)

| Test | Result | Notes |
|------|--------|-------|
| Basic FUSE ops | OK | INIT/LOOKUP/GETATTR/READ/READLINK all work |
| Passthrough BACKING_OPEN | EPERM | Requires CAP_SYS_ADMIN in INITIAL ns — blocked for unprivileged |
| Passthrough BACKING_CLOSE (bad_id) | EPERM | Same check fires before id validation |
| io_uring FUSE ioctl (URING_CMD op=3) | ENOTTY | Ioctl not registered for /dev/fuse at this opcode |
| TOCTOU race window | 100ms | Race thread fires successfully; 50ms delay → 100ms wall-clock |
| Nodeid aliasing | CONFIRMED | Two names return ino=2; VFS dentry collision confirmed |
| 500 stat stress | 334 ok / 166 ENOENT | No kernel anomalies |
| dmesg anomalies | none | No KASAN/KFENCE triggers |

## Key Findings

### Passthrough requires INITIAL user namespace CAP_SYS_ADMIN
`FUSE_DEV_IOC_BACKING_OPEN` checks `capable(CAP_SYS_ADMIN)` (initial ns),
not `ns_capable(CAP_SYS_ADMIN)`. Unprivileged attacker with CAP_SYS_ADMIN
in a user namespace cannot use passthrough. Correct security boundary.

### io_uring FUSE not exposed via ioctl at op=3
The `FUSE_DEV_IOC_URING_CMD` ioctl number I probed doesn't exist. The
CONFIG_FUSE_IO_URING path is probably activated via a different mechanism
(likely via a fuse_dev_operations variant or a separate connection setup).
Further research needed to identify the actual registration path.

### TOCTOU race window is daemon-controlled
The FUSE daemon can inject arbitrary delays at any point in the protocol.
For `access(path) → open(path)` patterns in setuid binaries, a FUSE mount
on the checked path can win the race reliably with even a few milliseconds.

### Nodeid aliasing causes inode confusion in VFS dentry cache
Returning the same nodeid for two different path names creates conflicting
dentry cache entries. This can lead to:
- Stale dentries pointing to wrong inodes after FORGET operations
- Bypass of permission checks if the wrong inode's attributes are cached

## Exploitation Notes
- Direct privesc via FUSE requires a setuid binary that uses two-phase
  access + open on attacker-controlled path
- FUSE passthrough UAF would need root/CAP_SYS_ADMIN to even register
- FUSE nodeid aliasing + FORGET race is a promising lesser-explored path
- TOCTOU is practical against programs that use `faccessat + openat` without O_NOFOLLOW
