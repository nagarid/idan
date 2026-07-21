# CHAIN-B: Epoch Asymmetry (Split-Brain Trigger) → HWM TOCTOU (False Durability)

## Metadata

| Field | Value |
|-------|-------|
| Chain ID | CHAIN-B |
| Findings Combined | [FINDING-005](../findings/FINDING-005-kraft-epoch-splitbrain.md) (stage 1) → [FINDING-002](../findings/FINDING-002-kraft-hwm-toctou.md) (stage 2) |
| Target | `apache/kafka` (KRaft consensus layer) |
| Component | `KafkaRaftClient` (both findings live in the same class) |
| Category | Distributed Consensus Bypass → Data Integrity Loss |
| Combined CVSS v3.1 Score | **9.1 CRITICAL** |
| Combined CVSS v3.1 Vector | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` |
| Combined CWE | CWE-362 (Race Condition) + CWE-670 (Incorrect Control Flow) + CWE-367 (TOCTOU) |
| Requires Auth | NONE — network access to controller port 9093 |
| MSK Affected | YES — MSK Standard / Multi-AZ clusters in KRaft mode (Kafka 3.3+) |

## Why This Chain Matters

FINDING-002's TOCTOU (false `acks=all` durability) only fires during a narrow, naturally-occurring race: a leader must be mid-demotion, still processing produce requests, at the exact moment `onUpdateLeaderHighWatermark` completes pending futures. That's why it's scored `AC:H` — attack complexity is high because the attacker can't force the window, only wait for it (e.g. hope an AZ failover happens at the right instant).

FINDING-005 turns that "hope for a race" into "manufacture the race on demand." Its PreVote/Vote epoch-comparison asymmetry (`>` vs `>=`) lets an attacker keep two nodes simultaneously believing they're valid leadership candidates at the same epoch boundary — which is precisely the demotion-in-flight condition FINDING-002 needs. Chaining them converts attack complexity from High to Low: the attacker no longer waits for natural network churn, they induce the exact epoch boundary condition directly via crafted Vote/PreVote traffic.

**Net effect:** the combined chain moves from two independent `7.4 HIGH` findings to a `9.1 CRITICAL` — not because impact changes (still integrity + availability, no confidentiality loss), but because attack complexity drops from High to Low once the race is reliably inducible instead of merely possible.

## Combined Attack Narrative

```
Attacker (network access to controller port 9093, zero credentials)
        │
        ▼
[Stage 1 — FINDING-005] Craft PreVote/Vote traffic exploiting the
  epoch asymmetry (lastEpoch == replicaEpoch):
     PreVote check: lastEpoch >  replicaEpoch → false → PASSES
     Vote    check: lastEpoch >= replicaEpoch → true  → REJECTED
  Two nodes accumulate disjoint PreVote majorities at the same epoch,
  both proceed toward election — one is about to be demoted from
  the other's perspective, but hasn't processed that yet.
        │
        ▼
[Bridge] Node A is now "leader that doesn't know it's about to be demoted"
  — exactly the precondition FINDING-002 needs, produced on demand
  instead of waited for.
        │
        ▼
[Stage 2 — FINDING-002] Producers with acks=all keep sending to Node A.
  onUpdateLeaderHighWatermark() completes appendPurgatory futures
  BEFORE re-checking quorum.isLeader(). Producer receives ack.
        │
        ▼
Node B wins the real election; Node A truncates its log on rejoin.
Records the producer believes are durably committed no longer exist.
```

## Step-by-Step Exploitation

1. Stand up the 3-node KRaft lab cluster (`deploy-yamls/kraft-cluster-config.yaml`), short election timeouts.
2. Start an `acks=all` producer against the current leader (reuse `payloads/finding-002`'s produce loop, embedded in FINDING-002's PoC).
3. Instead of relying on `docker compose restart` / `iptables` to *hope* for a demotion race (FINDING-002's standalone method), use `payloads/finding-005-vote-epoch-craft.py` to send crafted PreVote/Vote requests that hold two nodes at the `lastEpoch == replicaEpoch` boundary, forcing the asymmetric accept/reject outcome deterministically:
   ```bash
   python3 payloads/finding-005-vote-epoch-craft.py localhost 19093 <cluster-id>
   ```
4. With the epoch boundary condition now attacker-controlled rather than incidental, repeat the produce loop and confirm the confirmed-vs-received gap from FINDING-002's PoC appears reliably (not just occasionally, as in the standalone finding).
5. Compare producer-confirmed count vs consumer-received count — the gap now reproduces on demand instead of requiring a natural AZ failover window.

## Combined CVSS Justification

Both standalone findings share the same impact metrics (`C:N/I:H/A:H`) and differ from each other only cosmetically. The chain changes **Attack Complexity** from High to Low, since FINDING-005 removes the "must wait for a natural race" condition:

```
Standalone (AC:H): Exploitability = 8.22 * 0.85(AV:N) * 0.44(AC:H) * 0.85(PR:N) * 0.85(UI:N) = 2.221
                    Score = Roundup(5.177 + 2.221) = Roundup(7.398) = 7.4 HIGH   (each finding individually)

Chained (AC:L):     Exploitability = 8.22 * 0.85(AV:N) * 0.77(AC:L) * 0.85(PR:N) * 0.85(UI:N) = 3.887
                    Score = Roundup(5.177 + 3.887) = Roundup(9.064) = 9.1 CRITICAL
```

This is the clearest quantitative demonstration in this research set of why chains matter: the individual CVSS scores (7.4 + 7.4) understate the real risk when the two bugs sit in the same race window and one supplies the trigger the other needs.

## Amazon MSK Specific Impact

- MSK Multi-AZ KRaft quorums cross AZ boundaries — inter-AZ network conditions are exactly where FINDING-005's crafted Vote/PreVote traffic has the most effect, and exactly when FINDING-002's TOCTOU window naturally opens (AZ failover, rolling broker replacement, version upgrades).
- Chaining removes MSK's operational unpredictability as a mitigating factor: an operator might reasonably assume "false acks only happen during rare AZ incidents" — this chain shows an attacker with only network access to port 9093 can manufacture that incident on demand.
- Both stages target the KRaft controller port, not the broker data-plane listener — so this chain is scoped to whoever can reach 9093 (typically inter-broker/controller traffic within the cluster's security group), not general Kafka clients.

## Proposed Fix

Fixing either stage independently still leaves risk from the other:
1. **Stage 1 (FINDING-005):** make the epoch-illegality check symmetric (`lastEpoch >= replicaEpoch` for both PreVote and Vote) — see FINDING-005's fix.
2. **Stage 2 (FINDING-002):** re-validate `quorum.isLeader()` inside `onUpdateLeaderHighWatermark` before completing pending futures — see FINDING-002's fix.

Fixing FINDING-005 alone raises attack complexity back to High (removes the reliable trigger) but does not eliminate FINDING-002's underlying TOCTOU — natural network churn could still occasionally hit the race. Fixing FINDING-002 alone eliminates the false-ack outcome even if FINDING-005's asymmetry is left unpatched. **Both should be fixed**; FINDING-002's fix is the more load-bearing of the two since it closes the actual data-loss window.

## Detection

- `kafka.controller:type=KafkaController,name=ActiveControllerCount` transiently reading 0 or 2 across nodes, correlated with a burst of Vote/PreVote traffic on port 9093 from a single external source
- Compare `record-send-total` (producer) vs broker-side `MessagesInPerSec` during any period with `OfflinePartitionsCount > 0` — a sustained gap (not just a momentary blip) suggests the chain rather than incidental churn
- `LeaderEpochFileCache` truncation events on multiple nodes within the same short window, without a corresponding AWS-visible AZ event in CloudWatch (i.e., truncation with no infrastructure-level explanation) is a strong indicator of induced rather than natural churn
