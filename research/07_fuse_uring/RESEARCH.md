# FUSE io_uring Transport — Activation, Protocol, and Ring Teardown Race
## Kernel: 6.18.5 | Ubuntu 24.04 | CONFIG_FUSE_IO_URING=y

## Overview

Linux 6.14 added a new FUSE transport mode: rather than routing FUSE ops through
`/dev/fuse` read/write, the kernel can route them through io_uring rings
(`CONFIG_FUSE_IO_URING`). The feature is gated by a sysctl that is off by default:

```
/sys/module/fuse/parameters/enable_uring
```

This research maps the activation protocol, reverse-engineers the
`FUSE_IO_URING_CMD_REGISTER` command format (not documented in public headers),
characterizes the teardown behavior when in-flight ring requests are orphaned,
and assesses the attack surface.

---

## Attack Surface Summary

| Test | Finding |
|------|---------|
| T1: Negotiation | `FUSE_OVER_IO_URING` bit (flags2=0x200) confirmed in FUSE_INIT |
| T2: REGISTER | Works; iovec format reverse-engineered from kernel binary |
| T3: Teardown race | Ring close with in-flight SQEs: kernel cleanly aborts (no crash on 6.18.5) |
| T4: Sysctl | `enable_uring=Y` required; not set by default |

---

## The FUSE io_uring Transport Protocol

### Activation (T1)

The io_uring transport is negotiated during `FUSE_INIT`. The client sets
`FUSE_INIT_EXT` in `flags` and requests `FUSE_OVER_IO_URING` in `flags2`. If the
kernel supports it and `enable_uring=Y`, it echoes `FUSE_OVER_IO_URING` back.

```
FUSE_OVER_IO_URING = bit 41 in full 64-bit flags space
                   = bit 9 in flags2 = 0x200
```

After negotiation, ALL subsequent FUSE ops are routed through the io_uring rings
— the `/dev/fuse` fd goes silent. The daemon must register a ring queue before any
FUSE ops can be served.

### Ring Queue Registration (T2)

The daemon registers an io_uring ring as a FUSE queue using an `IORING_OP_URING_CMD`
SQE with `cmd_op = FUSE_IO_URING_CMD_REGISTER` (= 1). The ring **must** be created
with `IORING_SETUP_SQE128` (128-byte SQEs); without it, `fuse_uring_cmd` returns
`EOPNOTSUPP`.

#### `sqe->addr` is a `struct iovec[2]`, not a raw buffer

This is the key detail not visible from headers alone. `fuse_uring_register` calls:

```
import_iovec(READ, sqe->addr, 2, 2, rsp+0x20, rsp+0x28)
```

The two imported iovecs land as fast-path copies at `rsp+0x50` and `rsp+0x60`:

| Field | Location | Constraint | Purpose |
|-------|----------|-----------|---------|
| `iov[0].iov_base` | rsp+0x50 | any writable page | In-buffer: kernel writes FUSE request headers here |
| `iov[0].iov_len`  | rsp+0x58 | **> 0x11f (287)** | Must be large enough for headers |
| `iov[1].iov_base` | rsp+0x60 | any writable page | Out-buffer: kernel reads FUSE response args from here |
| `iov[1].iov_len`  | rsp+0x68 | **>= queue->max_payload** | Must hold full FUSE response |

`queue->max_payload` is computed in `fuse_uring_create` as:

```
max_payload = max(max(fc->max_write, 0x2000), fc->max_pages << 12)
```

With `max_write=65536` this is 65536. Using 128 KiB for `iov[1].iov_len` is safe.

#### `sqe->len` must equal exactly 2

```
cmpl $0x2, 0x18(%sqe)  → jne return(-EINVAL)
```

#### `qid` placement in the 128-byte SQE

```c
/*
 * cmd_req placed at sqe+48 (cmd[] start in 128-byte SQE):
 *   sqe+48 = cmd[0]  = flags     (8 bytes)
 *   sqe+56 = cmd[8]  = commit_id (8 bytes)
 *   sqe+64 = cmd[16] = qid       (uint16_t)
 */
struct fuse_uring_cmd_req {
    uint64_t flags;
    uint64_t commit_id;
    uint32_t qid;
    uint32_t pad;
};
```

The struct must be placed at `sqe+48` (not sqe+64) so `r->qid` (at struct offset 16)
lands at `sqe+64` where the kernel reads the queue ID.

#### REGISTER is a deferred operation — no immediate CQE

`fuse_uring_register` returns `0` on success but this propagates to `fuse_uring_cmd`
which returns `0xfffffdef` (-529) to `io_uring_cmd`. The kernel explicitly checks:

```asm
cmp $0xfffffdef, %ebx
je  hold_pending        ; holds request without generating CQE
```

This is `IOU_ISSUE_SKIP_COMPLETE` (or `IOU_PENDING`). The REGISTER SQE is held in
the kernel indefinitely — there is never a CQE for it. Waiting for a CQE deadlocks.
The correct check: poll the CQ ring non-blockingly; if no CQE arrives after a short
delay, the REGISTER was accepted.

### COMMIT_AND_FETCH (T3 context)

After REGISTER, the daemon pre-fills `FUSE_IO_URING_CMD_COMMIT_AND_FETCH` SQEs
(`cmd_op = 2`). These block in the kernel until a FUSE op arrives; then the kernel
fills the in-buffer with the FUSE request header and posts a CQE. The daemon handles
the op and re-submits the SQE to fetch the next op.

---

## Teardown Race (T3)

### Scenario

1. Register a FUSE ring queue (REGISTER SQE accepted, in-flight).
2. Submit N COMMIT_AND_FETCH SQEs — these block waiting for FUSE ops.
3. Close the io_uring ring fd while those SQEs are still in-flight.

### Expected danger

The kernel must abort in-flight `fuse_uring_req` objects on ring teardown. If
reference counting on the ring buffers is incorrect, the `fuse_uring_req` objects
and their pinned pages could be freed while the kernel still has a pointer to them
— a classic UAF.

### Result on 6.18.5

No crash, no OOPS. The kernel cleanly aborts each in-flight SQE with:

```
fuse: qid=0 commit_id 0 not found
fuse: FUSE_IO_URING_COMMIT_AND_FETCH failed err=-2
```

These are expected cleanup messages — the kernel searched for a commit_id=0 to
finalize, found none (since we never actually committed any op), and exited cleanly.

### Assessment

The teardown path appears correctly guarded on 6.18.5. The `fuse_uring_req`
reference counting introduced alongside the feature handles this scenario. This does
not mean the teardown path is bug-free — a more sophisticated race would need:

1. An actual round-trip FUSE op to flow through the ring (so `commit_id != 0`).
2. A racing thread that closes the fd at the precise moment the kernel is finalizing
   the request in `fuse_uring_commit_and_fetch`.
3. A tight timing window around `fuse_uring_req` put/get in `fuse_uring_uring_cmd`.

The simpler version (close with pending SQEs waiting for first op) is handled safely.

---

## Reverse Engineering Methodology

All kernel internals were derived from live disassembly via `/proc/kcore`:

```bash
# Resolve function address
addr=$(grep -w 'fuse_uring_register' /proc/kallsyms | awk '{print $1}')

# Read function binary
python3 -c "
import struct, sys
addr = 0x$addr
size = 1376
with open('/proc/kcore','rb') as f:
    # ... ELF PT_LOAD segment parsing ...
" > /tmp/fuse_uring_reg_full.bin

# Disassemble
objdump -D -b binary -m i386:x86-64 /tmp/fuse_uring_reg_full.bin
```

Key functions reversed:

| Function | Address | Size | Key findings |
|----------|---------|------|-------------|
| `fuse_uring_cmd` | 0xffffffff817027f0 | 688 B | -529 pending check at +0xc7 |
| `fuse_uring_register` | 0xffffffff81700ea0 | 1376 B | import_iovec call at +0xa3, len check at +0x11f |
| `fuse_uring_create` | 0xffffffff81700c80 | 320 B | max_payload computation |
| `io_uring_cmd` | 0xffffffff8189a410 | 512 B | dispatch to fuse_uring_cmd at +0xab |

---

## Affected Components

- `fs/fuse/iouring.c`: `fuse_uring_cmd`, `fuse_uring_register`, `fuse_uring_create`,
  `fuse_uring_commit_and_fetch`, `fuse_uring_teardown`
- `io_uring/uring_cmd.c`: `io_uring_cmd` — pending (-529) path

## Kernel Requirement

- `CONFIG_FUSE_IO_URING=y`
- `echo 1 > /sys/module/fuse/parameters/enable_uring`
- Minor >= 39 (from FUSE_INIT response `minor` field)
- Ring created with `IORING_SETUP_SQE128`

## CVE Potential

**Medium (currently).** The teardown race does not crash 6.18.5. However:

1. The attack surface is **novel and not widely tested**: most FUSE security research
   targets the permission model, not the io_uring transport. The ring teardown path
   was added in 6.14 and has had limited adversarial scrutiny.

2. The sysctl gate (`enable_uring=Y`) is off by default, but cloud providers running
   container workloads with FUSE-based overlay filesystems may enable it for
   performance. A malicious container process could trigger the race against a
   shared FUSE daemon.

3. The deferred REGISTER behavior (no CQE = accepted) is a subtle protocol detail
   that can cause race conditions in daemon implementations — daemons that
   incorrectly wait for a REGISTER CQE will hang, potentially causing mount
   deadlocks exploitable by unprivileged users who can trigger FUSE ops.

**Higher-confidence targets for future work:**

- `fuse_uring_commit_and_fetch` during concurrent `fuse_uring_teardown` — the
  in-progress-op path where `fuse_uring_req` is looked up by commit_id while
  teardown is destroying the queue.
- `fuse_uring_queue_destruct` refcount ordering against `fuse_uring_uring_cmd`
  callback.
