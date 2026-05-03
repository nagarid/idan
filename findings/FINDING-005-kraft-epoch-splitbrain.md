# FINDING-005: KRaft Epoch Asymmetry Between PreVote and Vote — Split-Brain

## Metadata

| Field | Value |
|-------|-------|
| Finding ID | FINDING-005 |
| Target | `apache/kafka` |
| Component | `KafkaRaftClient` |
| Source File | `raft/src/main/java/org/apache/kafka/raft/KafkaRaftClient.java` |
| Approximate Lines | ~2700–2750 (vote request handler, `isIllegalEpoch` computation) |
| Category | Distributed Consensus Bypass — Split-Brain Leadership |
| CVSS v3.1 Estimate | **7.5 HIGH** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H` |
| CWE | CWE-362: Race Condition; CWE-670: Always-Incorrect Control Flow Implementation |
| Requires Auth | NO — requires network access to the controller port (9093) |
| MSK Affected | YES — MSK clusters running Kafka 3.3+ in KRaft mode |

## Summary

In `KafkaRaftClient.handleVoteRequest()`, the epoch illegality check uses **different comparison operators** for PreVote (`>`) versus standard Vote (`>=`). At the boundary `lastEpoch == replicaEpoch`, a PreVote request passes while the corresponding Vote request is rejected. Under adversarial network conditions, this asymmetry allows two nodes to simultaneously accumulate PreVote majorities and proceed to election — potentially resulting in dual leaders and split-brain writes.

## Vulnerable Code (verbatim)

```java
// KafkaRaftClient.java — vote request handler (approximate lines ~2700-2750)
private VoteResponseData handleVoteRequest(
    RaftRequest.Inbound requestMetadata,
    boolean preVote
) {
    VoteRequestData request = (VoteRequestData) requestMetadata.data();
    int replicaEpoch      = request.candidateEpoch();
    int replicaId         = request.candidateId();
    int lastEpoch         = request.lastOffsetEpoch();
    long lastEpochEndOffset = request.lastOffset();

    /*
     * Validate the replica epoch and the log's last epoch.
     *
     * For a standard vote, the candidate increases the epoch before sending.
     * So lastEpoch < replicaEpoch is expected.
     *
     * For a PreVote, the prospective replica doesn't increase the epoch.
     * So lastEpoch == replicaEpoch is possible.
     *
     * ASYMMETRY: at lastEpoch == replicaEpoch:
     *   PreVote  check: E > E = false  → not illegal → PASSES
     *   Vote     check: E >= E = true  → ILLEGAL     → REJECTED
     */
    boolean isIllegalEpoch = preVote ? lastEpoch > replicaEpoch
                                     : lastEpoch >= replicaEpoch;

    if (isIllegalEpoch) {
        return buildVoteResponse(Errors.INVALID_REQUEST, false);
    }
    // ... continues to grant or deny vote based on log offset comparison
}
```

## Root Cause

The asymmetric comparison exists to accommodate the Raft PreVote optimization (where the epoch is not yet incremented). However, the boundary case `lastEpoch == replicaEpoch` is treated differently: a PreVote at this boundary is "not illegal" while a Vote at the same boundary is "illegal." This creates a window where a node can win a PreVote (at its current epoch E) but fail to win the subsequent Vote (also at epoch E). Under network partitions carefully timed to keep `lastEpoch == replicaEpoch` on two competing nodes, both can accumulate pre-vote majorities from disjoint quorum subsets, then both attempt election with their actual votes — resulting in split-brain.

## Attack Prerequisites

- Network access to broker controller port (9093) to inject or delay vote messages
- A network partition scenario (natural or induced) that splits the KRaft quorum asymmetrically
- Lab environment: Docker Compose cluster from `deploy-yamls/kraft-cluster-config.yaml`

## Step-by-Step Exploitation

1. Set up 3-node KRaft cluster with short election timeouts (see `deploy-yamls/kraft-cluster-config.yaml`)
2. Identify current leader and its epoch
3. Run `payloads/finding-005-vote-epoch-craft.py` to probe the epoch boundary behavior:
   ```bash
   python3 payloads/finding-005-vote-epoch-craft.py localhost 19093 MkU3OEVBNTcwNTJENDM2Qk
   ```
4. Induce a controlled network partition between nodes 1 and 2 while preserving connectivity for node 3:
   ```bash
   # On the Docker host:
   iptables -I FORWARD -s 172.20.0.2 -d 172.20.0.3 -j DROP
   iptables -I FORWARD -s 172.20.0.3 -d 172.20.0.2 -j DROP
   ```
5. Node 1 and Node 2 both time out and begin elections; Node 3 can vote for both due to timing
6. The epoch asymmetry means PreVotes succeed for both while actual Votes may conflict
7. Monitor for `SPLIT_BRAIN` indicators in broker logs

## Payload

See `payloads/finding-005-vote-epoch-craft.py` for both the logic proof and wire protocol framing.

```python
# Logic proof from finding-005-vote-epoch-craft.py:
def is_illegal_epoch(pre_vote: bool, last_epoch: int, replica_epoch: int) -> bool:
    if pre_vote:
        return last_epoch > replica_epoch   # strict GT
    else:
        return last_epoch >= replica_epoch  # GTE

# At boundary lastEpoch == replicaEpoch == 5:
print(is_illegal_epoch(True,  5, 5))  # False → PreVote PASSES
print(is_illegal_epoch(False, 5, 5))  # True  → Vote REJECTED
```

## Expected Outcome

The logic proof confirms the asymmetry. In a network-partition scenario, the broker logs may show two nodes declaring leadership at overlapping epochs, followed by log truncation when the partition heals.

## Amazon MSK Specific Impact

- **MSK Multi-AZ:** KRaft quorum spans availability zones. An AZ failure or inter-AZ network disruption is exactly the partition scenario that can trigger this asymmetry
- **MSK Maintenance:** During broker replacement or MSK version upgrades (rolling restart), epoch boundaries are frequently traversed — this is a time when the asymmetry is most exploitable
- **Silent data loss:** Combined with FINDING-002, the split-brain scenario caused by this asymmetry can lead to records confirmed by producers being silently discarded when the partition heals

## Proposed Fix

Use consistent comparison operators. Per the Raft protocol, `lastEpoch >= replicaEpoch` should be illegal for both PreVote and Vote, since it indicates the local log has seen records at the candidate's claimed epoch — meaning the candidate is not actually ahead:

```java
// Consistent GTE check for both PreVote and Vote:
boolean isIllegalEpoch = lastEpoch >= replicaEpoch;
```

Or alternatively, document and encode the precise intent with an explicit comment explaining why the boundary case differs, with corresponding unit test coverage.

## Detection

- **Broker logs:** Look for `"Epoch X already exists at offset"` and truncation messages on multiple nodes simultaneously
- **KRaft metrics:** `kafka.controller:type=KafkaController,name=ActiveControllerCount` should always be exactly 1; if it momentarily shows 0 or 2, split-brain occurred
- **Log offset divergence:** Compare partition end offsets across all replicas — divergence indicates dual-leader writes
