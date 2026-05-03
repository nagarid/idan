# nf_tables Attack Surface Research
## Kernel: 6.18.5 | Ubuntu 24.04

## Attack Vector
Unprivileged user → `unshare --user --map-root-user --net` → CAP_NET_ADMIN
in isolated user+net namespace → nf_tables full access via NFNL_SUBSYS_NFTABLES.

## Subsystem Architecture

```
User space (nft/netlink) 
       │
       ▼
nfnetlink_rcv_batch()          ← single mutex for entire batch
       │
       ├─ nft_check phase      ← per-op validation, no kernel state changed
       │       │
       │       └─ nft_table_lookup / nft_chain_lookup / nft_rule_lookup
       │
       └─ nft_commit phase     ← applies changes, calls activate/deactivate
               │
               ├─ nft_rule_activate()
               ├─ nft_chain_commit_update()
               └─ nf_tables_commit_release()  ← deferred via call_rcu()
```

## High-Value Targets

### 1. pipapo COW + GC timer race

`nft_set_pipapo` (interval sets, >= 5.6) uses copy-on-write for atomic updates:
- `nft_pipapo_commit()` → `nft_set_pipapo_activate()` swaps working copy via RCU
- GC timer: `nft_set_pipapo_gc()` fires independently, walks elements

Race window:
1. GC fires, acquires RCU read lock, starts walking match->f[i].rules
2. Transaction starts, creates pipapo clone via `pipapo_clone()`
3. Transaction commits, `nft_pipapo_commit()` does `rcu_assign_pointer(priv->match, clone)`
4. RCU grace period starts - OLD match memory still valid
5. GC continues on old match, calls `nft_set_elem_destroy()` on elem
6. Same elem exists in clone, double-free path IF refcounting is wrong

Relevant functions: `nft_set_pipapo_gc`, `pipapo_clone`, `nft_pipapo_commit`

### 2. nft_verdict chain binding counter during concurrent transactions

From CVE-2024-1086 (patched): `nft_verdict_init` increments chain use counter.
The fix introduced `nft_chain_add` / `nft_chain_del` pair.

New angle: batch transactions with multiple NEWRULE ops referencing the same chain.
The `use` counter is incremented during `nft_rule_activate` (commit phase).
If a second concurrent batch (via separate netlink socket) processes simultaneously...
Actually: nfnetlink holds `nfnl_lock` - single-threaded. But deferred GC via
`call_rcu` runs outside the lock. 

### 3. nft_dynset + timeout + set GC interaction

`nft_dynset` adds elements dynamically during packet processing.
Set GC runs in softirq context (timer_softirq via `nft_set_gc_seq_begin`).
If element added via dynset has timeout=0 (immediate expiry)...

### 4. nft_set_rbtree ordered element activation

`nft_rbtree_activate` / `nft_rbtree_deactivate` toggle element visibility.
During transaction abort (`nft_abort`), elements are deactivated but not freed.
If the same transaction batch adds then immediately removes set elements,
the rbtree internal pointers might be in inconsistent state.

### 5. nft_socket cgroupv2 - cross-namespace information leak

`nft_socket` with `NFT_SOCKET_CGROUPV2` key:
- Traverses `sock->sk_cgroup` hierarchy
- In a user namespace, this can reach cgroup paths from the host namespace
- Not direct privesc but information leak → KASLR bypass input

## Exploitation Primitives

Standard kernel heap exploit path:
1. **Info leak**: `kptr_restrict=0` + `/proc/kallsyms` → direct kernel symbol read
2. **Heap spray**: NFT_MSG_NEWSET with controlled-size names fills slab
3. **UAF trigger**: race or logic bug frees object while ref held
4. **Write primitive**: overwrite `nft_set->ops` or `nft_chain->type` function pointer
5. **Pivot**: call through corrupted function pointer → ROP → commit_creds(init_cred)

## Notes on 6.18.5 Mitigations

- CONFIG_BPF_JIT=n → no BPF JIT spray
- kptr_restrict=0 → root can read /proc/kallsyms; non-root sees zeros
- KASAN/KFENCE: not triggered by test suite; kernel 6.18.5 appears patched
- CONFIG_SLAB_FREELIST_RANDOM=y, CONFIG_SLAB_FREELIST_HARDENED=y
- CONFIG_HARDENED_USERCOPY=y, CONFIG_FORTIFY_SOURCE=y
- CONFIG_STACKPROTECTOR_STRONG=y
- CONFIG_SECURITY_LANDLOCK=n (absent — no landlock restriction to bypass)

## Test Results (nft_poc.c, kernel 6.18.5)

| Test | Status | Notes |
|------|--------|-------|
| pipapo GC race | No crash | 384/512 elements added; no KASAN triggered |
| rbtree abort | No crash | EEXIST returned correctly; abort path not triggered |
| dynset 1ms timeout | Clean | Elements expired and re-added cleanly |
| concurrent transactions | No crash | Two sockets, concurrent ops; no anomalies |
| heap spray | 64 sets / 32 freed | Slab hole creation works |

## Protocol Notes (Raw Netlink Encoding)

### Pipapo interval element encoding
Real `nft` uses "interval-end pair" format — NOT `NFTA_SET_ELEM_KEY_END`.
For IP X in an interval set, the ELEMENTS list contains:
1. Sentinel: `0.0.0.0` + `NFTA_SET_ELEM_FLAGS=NFT_SET_ELEM_INTERVAL_END=0x1`
2. Start: `X` (no flags)
3. End: `X+1` + `NFTA_SET_ELEM_FLAGS=NFT_SET_ELEM_INTERVAL_END=0x1`

### Batch encoding
- BATCH_BEGIN nlmsg_type = 0x10 (kernel accepts without subsystem prefix)
- nfgenmsg.res_id = htons(NFNL_SUBSYS_NFTABLES) = htons(10) — REQUIRED
- Real nft sends type as 0x0a10 but kernel accepts 0x10 equally
