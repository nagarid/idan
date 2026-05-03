# BPF Verifier / seccomp cBPF Attack Surface Research
## Kernel: 6.18.5 | Ubuntu 24.04

## Kernel Config / System State

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=n               ← No JIT — interpreted only (__bpf_prog_run)
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y        ← classic BPF for seccomp accessible
unprivileged_bpf_disabled=2    ← permanently locked, root cannot change
```

## Access Model

eBPF (`bpf(2)` syscall) is fully blocked:
- `unprivileged_bpf_disabled=2` means even root cannot re-enable it
- `BPF_MAP_CREATE` returns `EPERM` regardless of namespace capabilities
- User namespace `CAP_SYS_ADMIN` insufficient — kernel uses `capable()` not `ns_capable()`

**Classic BPF (cBPF) via seccomp IS accessible unprivileged:**
```
PR_SET_NO_NEW_PRIVS=1  (no privileges needed)
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)  ← works for any user
```

cBPF programs are verified by `bpf_check_classic()` in `net/core/filter.c`,
then converted to eBPF internal representation via `bpf_convert_filter()`.
Without JIT, execution goes through `__bpf_prog_run()` (eBPF interpreter).

## High-Value Attack Surfaces

### 1. cBPF Verifier Boundary Cases

`bpf_check_classic()` enforces these limits (all confirmed blocking on 6.18.5):
- `len=0` → EINVAL
- `len > BPF_MAXINSNS (4096)` → EINVAL
- Unconditional jump past end (`BPF_JA k >= remaining_insns`) → EINVAL
- Backward unconditional jump (`BPF_JA k=0xFFFFFFFF`) → EINVAL
- Conditional jump jt/jf past end → EINVAL
- `BPF_DIV k=0` (divide by zero) → EINVAL
- `BPF_ST M[k]` with `k >= BPF_MEMWORDS (16)` → EINVAL

Boundary accepted: `len=4096` (exactly BPF_MAXINSNS) and `M[15]` (last scratch word).

The conversion path `bpf_convert_filter()` is a potential attack surface — a cBPF
instruction that passes the classic verifier but produces invalid eBPF bytecode
could theoretically cause issues, though none found on 6.18.5.

### 2. Filter Stacking — Memory Exhaustion

Each `prctl(SECCOMP_MODE_FILTER)` call chains a new filter:
- On 6.18.5 there is **no hard depth limit** (kernel removed `MAX_SECCOMP_FILTER_DEPTH=256`
  or raised it past 3641)
- Limit is memory: stacking ~3641 filters on this system → **ENOMEM**
- Each filter consumes a `seccomp_filter` struct + copy of the `sock_filter` array
- Unprivileged user can exhaust kernel memory by chaining thousands of single-insn filters
- Effect: DoS against the process itself (no other-process impact)

### 3. SECCOMP_RET_USER_NOTIF — Syscall Interception

`SECCOMP_FILTER_FLAG_NEW_LISTENER` (kernel 5.0+, 6.18.5 supports):
```c
// Returns a file descriptor; holder can intercept all matched syscalls
listener_fd = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
```

The listener fd holder receives a `struct seccomp_notif` for every matched syscall:
- Full `seccomp_data`: syscall number, arch, instruction pointer, all 6 args
- Supervised process blocks until supervisor responds
- Supervisor can: ALLOW, KILL, return custom error/value

**Attack surface: listener fd leak**
- The listener fd is inheritable across `fork()` unless `O_CLOEXEC`
- If an unprivileged process obtains a listener fd for a privileged process's
  USER_NOTIF filter, it gains full visibility + control of all intercepted syscalls
- Container runtimes (gVisor, sysbox, nydus-snapshotter) use USER_NOTIF — a
  leaked listener fd = container escape mechanism

### 4. SECCOMP_IOCTL_NOTIF_ADDFD — FD Injection into Supervised Process

Kernel 5.9+: supervisor can atomically inject a file descriptor into the supervised
process and use it as the return value of the intercepted syscall:

```c
struct seccomp_notif_addfd addfd = {
    .id         = notif.id,
    .flags      = SECCOMP_ADDFD_FLAG_SEND,  /* combine inject + reply */
    .srcfd      = attacker_controlled_fd,
    .newfd      = -1,                        /* kernel chooses fd number */
    .newfd_flags= O_CLOEXEC,
};
ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
/* supervised process's openat() returns the injected fd number */
```

**Demonstrated:** Child opens `/proc/self/status`, supervisor injects fd pointing to
`/proc/1/cmdline`. Child receives an fd that appears to be the result of its own
`open()` but reads a completely different file.

**Privilege escalation scenario:**
1. Container runtime uses USER_NOTIF to intercept file access in a privileged container
2. Attacker leaks the listener fd (e.g., through fd inheritance race in multi-threaded runtime)
3. Attacker intercepts privileged container's `open("/etc/sudoers")` 
4. Injects fd to attacker-controlled file with `ALL=(ALL) NOPASSWD: ALL`
5. Privileged container reads attacker content, grants full sudo

### 5. seccomp Pointer-Arg Blindness — Content-Based Policy Bypass

`seccomp_data.args[]` contains syscall ARGUMENT VALUES (pointer addresses for
buffer/path arguments), never the pointed-to memory content.

A filter cannot:
- Check what pathname `openat()` was called with (only sees pointer value)
- Check what `write()` buffer contains (only sees pointer + length)
- Distinguish `write(1, "safe", 4)` from `write(1, "secret", 6)`

**TOCTOU extension via USER_NOTIF:**
If supervisor tries to do content-based checks by calling `process_vm_readv()` on
the supervised process's buffer, there is a TOCTOU window: another thread in the
supervised process can change the buffer between supervisor's read and actual
syscall execution. This is a fundamental limitation of the seccomp architecture.

## Test Results (bpf_poc.c, kernel 6.18.5)

| Test | Result | Notes |
|------|--------|-------|
| T1: cBPF verifier edges | All EINVAL ✓ | 9/9 boundary cases enforced |
| T2: filter stacking | ENOMEM at 3641 | No hard count limit on 6.18.5 |
| T3: USER_NOTIF basic | WORKING | Intercepted openat(), CONTINUE reply |
| T4: ADDFD injection | CONFIRMED | Child got injected fd, read wrong file |
| T5: pointer blindness | CONFIRMED | Filter passed both SAFE and SECRET writes |

## Key Findings

### eBPF fully locked on this system
`unprivileged_bpf_disabled=2` is a permanent lockdown. No eBPF maps, programs,
or BPF syscall operations available to any user. Only cBPF via seccomp works.

### cBPF verifier is solid on 6.18.5
All boundary checks enforced. The cBPF→eBPF conversion path (`bpf_convert_filter`)
didn't produce any exploitable states in our test cases. No CVE-style verifier
bypass found on this kernel version.

### USER_NOTIF + ADDFD is the most powerful primitive
This is a designed mechanism (used by container runtimes, seccomp-agent, etc.)
that is extremely powerful when misused. The listener fd:
- Provides full syscall transparency (all args visible)
- Allows arbitrary response spoofing (fake return values, errors)
- Allows fd injection into the target (ADDFD primitive)
- Persists across exec (unless the exec is setuid with AT_SECURE)

The kernel does NOT have a capability requirement for the USER_NOTIF API itself
once `no_new_privs` is set — any unprivileged process can create a USER_NOTIF
listener for its own children.

### Filter stacking DoS
The memory-based limit (3641 on this machine) rather than a hard count limit
means an unprivileged user can exhaust `~3641 * sizeof(seccomp_filter)` bytes
of kernel memory. Not a security boundary break, but relevant for container
environments with shared kernel memory.

## Exploitation Notes

- Direct privesc via cBPF/seccomp alone is not feasible on 6.18.5
- The USER_NOTIF+ADDFD primitive requires controlling a privileged process's
  seccomp listener fd — achievable if a container runtime has a fd leak bug
- The pointer-blindness TOCTOU is only exploitable if a seccomp supervisor
  does content-based access control (unusual in practice)
- Most realistic attack vector: exploit a container runtime's USER_NOTIF
  integration (gVisor, sysbox, etc.) to gain listener fd for privileged workload
