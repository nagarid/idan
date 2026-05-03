# cgroup Resource Accounting Side-Channel Research
## Kernel: 6.18.5 | Ubuntu 24.04

## Kernel Config

```
CONFIG_CGROUPS=y
CONFIG_MEMCG=y            ← memory cgroup v1 + v2
CONFIG_MEMCG_V1=y
CONFIG_CGROUP_BPF=y       ← cgroup BPF hooks compiled in
CONFIG_CGROUP_FREEZER=y   ← cgroupv1 freezer
CONFIG_CGROUP_PERF=y      ← perf counters per cgroup
CONFIG_BLK_CGROUP=y       ← block I/O per cgroup
```

**Note on cgroup BPF**: `CONFIG_CGROUP_BPF=y` compiles in the hooks but all
`BPF_PROG_ATTACH` operations still go through `bpf(2)` which is blocked by
`unprivileged_bpf_disabled=2`. cgroup BPF is effectively inaccessible.

## System State

- cgroupv1 hierarchy: cpu, cpuacct, memory, devices, freezer, blkio, pids
- cgroupv2 unified: mounted at `/sys/fs/cgroup/unified`, limited controllers
- `memory.move_charge_at_immigrate = 0` (default): existing pages stay in
  old cgroup when process moves; only NEW allocations go to new cgroup
- cgroupv1 stat files are world-readable (`-r--r--r--`)

## Access Model

cgroupv1 operations require:
- CAP_SYS_ADMIN in initial user namespace to create/move between cgroups
- BUT: stat files (`memory.usage_in_bytes`, `memory.stat`) are world-readable
  by any process, regardless of capabilities

cgroupv2 delegation: a cgroup dir with write permissions for a user allows
creating sub-cgroups without CAP_SYS_ADMIN (used for rootless containers).

## High-Value Attack Surfaces

### 1. Memory Usage Oracle (memory.usage_in_bytes)

`/sys/fs/cgroup/memory/<cg>/memory.usage_in_bytes` tracks total resident
memory of all processes in the cgroup, updated synchronously on each page fault.

**Resolution**: 4096 bytes (1 page)
**Attack**: Two processes in the same cgroup — observer reads usage before/after
target's operation. Delta reveals exact page-count change caused by target.

```
before = read(memory.usage_in_bytes)
[target allocates N pages]
after  = read(memory.usage_in_bytes)
delta  = after - before  /* = N * 4096 bytes */
```

Observable patterns:
- RSA key generation: different key sizes → different heap allocation sizes
- AES S-box cache fill: first access faults pages, subsequent accesses don't
- Memory-mapped file loads: number of pages loaded = file size / 4096

**Demonstrated**: Parent correctly infers child's 256KB vs 64KB allocation choice
(simulating a 1-bit secret) by reading cgroup usage before/after child signals.
Delta = 262144 bytes (64 pages) exactly.

### 2. Threshold eventfd Notification — Covert Channel

`cgroup.event_control` (cgroupv1) allows registering an eventfd that fires when
`memory.usage_in_bytes` crosses a threshold:

```
write(event_control, "<efd> <ufd> <threshold>\n")
select(efd, ...)  /* blocks until threshold crossed */
```

**Covert channel**: One process (sender) allocates above threshold (bit=1) or
stays below (bit=0). Another process (receiver) polls the eventfd.
- No shared memory needed
- No explicit IPC
- Works across process boundaries within the same cgroup
- Each threshold crossing delivers one eventfd notification

**Demonstrated**: Child allocated 1MB to cross baseline+512KB threshold; parent
received eventfd notification (count=1).

### 3. cgroup Namespace Information Leak

`/proc/self/cgroup` shows the HOST cgroup path even inside a user namespace,
unless the process explicitly creates a new cgroup namespace (`CLONE_NEWCGROUP`).

Example leak from container process:
```
3:memory:/process_api/019decdc-807d-73c0-820e-ace273ed6294
```

This reveals:
- Container runtime name (`process_api`) → identifies runtime vendor
- Container UUID (`019decdc-807d-73c0-820e-ace273ed6294`) → unique identifier
  usable for targeted attacks or container enumeration
- Container hierarchy depth → number of nested containers

Many container runtimes (Docker pre-20.10, older Kubernetes) do NOT create
`CLONE_NEWCGROUP`, leaving host cgroup paths visible.

### 4. Cross-Cgroup Stat Reading

cgroupv1 stat files are world-readable. Any process on the system can read:
```
-r--r--r-- memory.usage_in_bytes   — exact byte count of resident memory
-r--r--r-- memory.stat             — detailed breakdown (cache, rss, swap, ...)
-r--r--r-- memory.failcnt          — number of OOM events
-r--r--r-- memory.oom_control      — OOM kill counter
```

An unprivileged attacker with filesystem access to `/sys/fs/cgroup/memory/`
can monitor any cgroup's memory activity in real-time. This applies to:
- Other containers on the same host
- Privileged system services
- Any process in a named cgroup

Combined with the memory oracle: read sibling container's usage periodically to
detect cryptographic operations (key generation, TLS handshake) by timing.

### 5. cgroup Freezer — Denial of Service

`freezer.state` (cgroupv1) or `cgroup.freeze` (cgroupv2) halts all processes in
a cgroup. If the attacker has write access to the cgroup directory:
- cgroupv1: `echo FROZEN > freezer.state` → equivalent to SIGSTOP for all tasks
- cgroupv2: `echo 1 > cgroup.freeze` → same effect

Use case for DoS:
- In a delegation model (rootless containers), user can freeze their own subtree
- If a container runtime bug allows cross-cgroup writes, freeze victim container
- Freeze a crypto service → time-sensitive operations (TLS, SSH) break

**Demonstrated**: Child placed in freezer cgroup, `freezer.state` set to FROZEN,
child enters `D` (disk sleep) state (kernel suspended task).

## Test Results (cgroup_poc.c, kernel 6.18.5)

| Test | Result | Notes |
|------|--------|-------|
| T1: Memory oracle | CORRECT (delta=262144) | 256KB alloc inferred from cgroup counter |
| T2: eventfd threshold | EVENT FIRED (count=1) | 1MB alloc crossed threshold |
| T3: namespace leak | CONFIRMED | Host path `/poc_sc` visible from user ns |
| T4: cross-cgroup read | CONFIRMED | 986MB process_api cgroup readable |
| T5: freezer DoS | CONFIRMED | State=FROZEN, process in D state |

## Key Findings

### Memory oracle is the most practical attack

The oracle works at 4096-byte granularity, is synchronous (updates on page fault),
and requires no privileges beyond being in the same cgroup. In cloud environments
where multiple containers share a cgroup hierarchy, this enables:
1. Detecting when a target container is doing cryptographic work
2. Measuring the exact size of allocations (→ key size inference)
3. Timing attacks against memoized computations (cache miss = page fault)

### World-readable stats are the lowest-barrier attack

No cgroup membership required. Any unprivileged process can `cat` memory stats
of any cgroupv1 cgroup on the host. This is a design choice in cgroupv1 (changed
in cgroupv2 with proper permission delegation), not a bug, but a significant
information leak in shared-host environments.

### cgroup BPF is inaccessible on this system

Despite `CONFIG_CGROUP_BPF=y`, the `bpf(BPF_PROG_ATTACH)` path is blocked
by `unprivileged_bpf_disabled=2`. Attaching programs to cgroup hooks (ingress/
egress network, socket creation, sysctl) requires root + `bpf()` syscall access.
No workaround found.

## Exploitation Notes

- Memory oracle requires co-location in the same memory cgroup — practical in
  multi-tenant cloud environments or when attacker controls one container
- eventfd covert channel bypasses seccomp `write()` filters (uses cgroup, not IPC)
- Namespace leak is exploitable in any container runtime without CLONE_NEWCGROUP
- Cross-cgroup reading has zero barrier — works from any unprivileged process
- Freezer DoS requires cgroup write permissions (usually CAP_SYS_ADMIN for v1)
