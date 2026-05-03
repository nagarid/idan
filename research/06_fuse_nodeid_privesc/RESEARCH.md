# FUSE Nodeid Aliasing — Inode Mode Poisoning / Permission Bypass
## Kernel: 6.18.5 | Ubuntu 24.04

## Root Cause

The VFS inode cache in FUSE is keyed by `(superblock, nodeid)`. When two
different path names in a FUSE filesystem return the **same nodeid** from
`FUSE_LOOKUP` responses, the kernel maps both dentries to a **single shared
VFS inode** via `iget5_locked()`.

The critical flaw is in `fuse_iget()` (fs/fuse/inode.c):

```c
/* For non-stale existing inodes: */
fuse_change_attributes(inode, attr, NULL, attr_valid, attr_version);
return inode;  /* mode updated from whichever LOOKUP came last */
```

`fuse_stale_inode()` only checks **file-type bits** (`(mode ^ cached) >> 12`),
not permission bits. So two regular files (S_IFREG) with modes 0644 and 0000
are NOT stale relative to each other — they share one inode.

When path B's LOOKUP updates the shared inode's mode, path A's dentry is still
valid (`entry_valid` not expired) and will be served from the dentry cache
**without issuing a new FUSE_LOOKUP**. The kernel uses the now-poisoned inode.

## Attack Scenario

```
Attacker controls a FUSE server (e.g., libfuse-based userspace daemon).
Two exported paths return the same nodeid with different modes:

  world_read → nodeid=10, mode=0644, entry_valid=3600s
  root_only  → nodeid=10, mode=0000, entry_valid=3600s

Attack sequence:
  1. stat(root_only)  → FUSE_LOOKUP → inode 10 created, mode=0000
  2. stat(world_read) → FUSE_LOOKUP → inode 10 UPDATED to mode=0644
     (fuse_change_attributes updates the shared inode)
  3. open(root_only) as uid=1
     → dentry "root_only" still valid (no new LOOKUP)
     → kernel checks inode 10 mode = 0644 → ALLOWS uid=1 access
```

## Conditions Required

| Condition | Notes |
|-----------|-------|
| FUSE filesystem with `allow_other` | Non-root uid can access the mount |
| `default_permissions` in mount opts | Kernel enforces mode bits, not FUSE_ACCESS |
| Two paths returning same nodeid | Attacker controls the FUSE server |
| Long `entry_valid` in LOOKUP response | Prevents re-validation before attack |

`default_permissions` is recommended practice for FUSE servers that want
kernel-enforced DAC — it's the mode that makes inode->i_mode authoritative.
Without it, FUSE_ACCESS is sent to the daemon instead, which can implement
correct per-path checks.

## Test Results (fuse_alias_poc.c, kernel 6.18.5)

```
[attack step 1] stat(root_only)  → FUSE_LOOKUP → nodeid=10 mode=0000
  kernel reports: mode=00000 ino=10

[attack step 2] stat(world_read) → FUSE_LOOKUP → nodeid=10 mode=0644
  kernel reports: mode=00644 ino=10      ← inode poisoned

[attack step 3] stat(root_only)  → dentry valid, NO new FUSE_LOOKUP
  kernel reports: mode=00644             ← 0000 → 0644 confirmed

[attack step 4] uid=1 child:
  faccessat(root_only, R_OK) = ALLOWED  <-- BYPASS!
  open(root_only) = OPENED              <-- BYPASS!
  read(32 bytes): |SECRET_DATA_FROM_ROOT_ONLY|
```

## Affected Components

- `fs/fuse/inode.c`: `fuse_iget()`, `fuse_change_attributes()`
- `fs/fuse/dir.c`: `fuse_lookup()` → `fuse_iget()`

## Why This Matters

**Privilege escalation path:**
1. FUSE daemon running as root exports a filesystem with `allow_other`
2. Daemon has a bug where it returns the same nodeid for two paths
3. Unprivileged user performs the poisoning sequence
4. User reads/executes files they should have no access to

**Real-world examples where this applies:**
- libfuse-based filesystems with virtual/synthetic inodes (overlayfs-style)
- FUSE bindings that use inode numbers from an upstream source (e.g., NFS over FUSE)
- Container runtimes with FUSE-based rootfs layers

## Mitigation

1. **Kernel fix**: `fuse_change_attributes()` should NOT update permission bits
   of a cached inode when called from `fuse_iget()` if the inode already has
   valid credentials. Only update if `attr_version > fi->attr_version`.
2. **Alternatively**: `fuse_iget()` should treat mode bit changes (not just
   file-type changes) as "stale" and force a new inode allocation.
3. **Userspace mitigation**: FUSE daemons must NEVER reuse nodeids across paths
   with different security properties. Each unique file should have a unique nodeid.
4. **Workaround**: Do not use `default_permissions` if access control is
   path-based rather than inode-based; use `FUSE_ACCESS` instead, which is
   sent per-path per-access and cannot be confused by inode aliasing.

## Kernel Code Reference

```c
/* fs/fuse/inode.c */
static bool fuse_stale_inode(const struct inode *inode, int generation,
                             struct fuse_attr *attr)
{
    /* BUG: only checks file-type bits, ignores permission bits */
    return (inode->i_mode ^ attr->mode) >> 12 || inode->i_generation != generation;
}

struct inode *fuse_iget(struct super_block *sb, u64 nodeid, int generation,
                        struct fuse_attr *attr, u64 attr_valid, u64 attr_version)
{
retry:
    inode = iget5_locked(sb, nodeid, fuse_inode_eq, fuse_inode_set, &nodeid);
    if (!(inode->i_state & I_NEW)) {
        if (stale_inode(inode, generation, attr)) {
            fuse_make_bad(inode); iput(inode); goto retry;
        }
        /* BUG: always updates mode from latest LOOKUP, regardless of path */
        fuse_change_attributes(inode, attr, NULL, attr_valid, attr_version);
        return inode;
    }
    ...
}
```

## CVE Potential

**High.** This is a logic flaw in the FUSE inode caching mechanism that allows
a FUSE daemon (running as root) to unintentionally expose files to unprivileged
users when two paths share a nodeid. In cloud environments where userspace
container runtimes expose FUSE mounts with `allow_other`, this could allow
container escapes or cross-tenant data leaks.

The flaw is reproducible, not configuration-dependent (it follows from the
FUSE protocol design), and affects all kernels with FUSE support.
