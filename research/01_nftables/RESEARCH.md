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

### 1. nft_trans_gc pipeline — analysis and confirmed non-exploitability

**Initial hypothesis (INCORRECT):** `nft_trans_gc_elem_add()` stores expired elements
without a bounds check, allowing >507 elements to overflow a kmalloc-4k slab boundary.

**Disassembly findings (kernel 6.18.5, via /proc/kcore):**

`nft_trans_gc_alloc` (0xffffffff81c32ab0) calls `kmalloc(0x838, GFP_KERNEL|GFP_ZERO)`:
- Requested size: 0x838 = 2104 bytes → kmalloc-4k slab object = **4096 bytes**
- Header size: 40 bytes (gc->count is a u16 at offset 0x24; gc->elems[] starts at 0x28)
- Theoretical elements before slab OOB: (4096 - 40) / 8 = **507**
- Theoretical elements before alloc OOB: (2104 - 40) / 8 = **258**

`nft_trans_gc_elem_add` (0xffffffff81c32bd0): confirmed NO internal bounds check:
```asm
movzwl 0x24(%rdi),%eax  ; count = gc->count
lea    0x1(%rax),%edx
mov    %dx,0x24(%rdi)   ; gc->count++
mov    %rsi,0x28(%rdi,%rax,8) ; gc->elems[count] = elem ← NO CHECK
ret
```

**Effective bounds check — NFT_TRANS_GC_BATCHCOUNT = 0x100 = 256:**
- `nft_trans_gc_queue_sync` (0xffffffff81c32d70): `cmpw $0x100, 0x24(%rdi); je flush`
- `nft_trans_gc_queue_async` (0xffffffff81c32c00): identical check
- All 7 callers of elem_add (pipapo_gc, nft_rbtree_gc×2, __nft_rbtree_insert×3,
  nft_rhash_gc) call queue_sync or queue_async BEFORE elem_add
- With 256 elements: last write at 40 + 255×8 = **2080 bytes** < 2104 ✓ No OOB

**GC trigger model:**
- `nft_pipapo_gc_init` / `nft_rbtree_gc_init`: both just write jiffies to last_gc. NO timer.
- `nft_pipapo_commit` / `nft_rbtree_commit`: call GC inline after `jiffies - last_gc >= gc_interval`.
- GC runs exclusively under `nfnl_lock` (single-threaded). No race condition possible.

**Conclusion:** No exploitable bug in this path. The 256-element batch limit prevents OOB.
Any overflow attempt (e.g. 520 elements) results in ceil(520/256) = 3 safe gc transactions.

### 2. nft_verdict chain binding counter during concurrent transactions

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

## Test Results (nft_poc.c + nft_gc_oob.c investigation, kernel 6.18.5)

| Test | Status | Notes |
|------|--------|-------|
| pipapo GC race | Not reproducible | GC is commit-triggered under nfnl_lock; no timer race |
| rbtree abort | No crash | EEXIST returned correctly; abort path not triggered |
| dynset 1ms timeout | Clean | Elements expired and re-added cleanly |
| concurrent transactions | No crash | Two sockets, concurrent ops; no anomalies |
| heap spray | 64 sets / 32 freed | Slab hole creation works |
| nft_trans_gc OOB (nft_gc_oob.c) | Not reproducible | NFT_TRANS_GC_BATCHCOUNT=256 prevents OOB; incorrect analysis |

## nft_gc_oob.c Analysis (Post-Mortem)

`nft_gc_oob.c` was written to trigger an OOB write via pipapo GC processing 520 expired
elements. **The bug does not exist** for the following confirmed reasons:

1. **NFT_TRANS_GC_BATCHCOUNT = 256** (not unbounded as assumed):
   Both `nft_trans_gc_queue_sync` and `nft_trans_gc_queue_async` compare `gc->count`
   against 0x100 = 256 before each element addition. When count reaches 256, the current
   gc is flushed and a new one allocated. 520 elements → 3 transactions (256, 256, 8).

2. **No GC timer**: `nft_pipapo_gc_init` only initializes `last_gc = jiffies`. The
   pipapo GC runs inline in `nft_pipapo_commit()` under `nfnl_lock`.

3. **256 < 258 elements fits within 2104-byte allocation**: Even without queue_sync, the
   2104-byte struct can safely hold (2104-40)/8 = 258 elements before overflowing its
   own allocation, far below the 507-element slab boundary.

The heap grooming approach (msg_msg spray + pipapo_gc) also failed due to SLAB_FREELIST_RANDOM
shuffling slab object order — physical adjacency assumptions were incorrect.

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
