/*
 * Source: apache/kafka trunk
 * File: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/distributed/DistributedHerder.java
 * Lines: 1721-1730 (isLeader, leaderUrl), 186-220 (member variables)
 *
 * FINDING-010: DistributedHerder leader check uses string equality — no cryptographic proof.
 *
 * isLeader() returns true when assignment.leader() (a plain String member ID)
 * equals member.memberId() (the local worker's group member ID). Both values are
 * populated from the Kafka consumer group protocol — specifically from records
 * written to internal Connect config/status topics by the group coordinator.
 *
 * There is no cryptographic proof that the assignment came from a legitimate
 * coordinator. If an attacker can write to __connect-configs or __connect-offsets
 * (topics that require only WRITE ACL on the internal namespace), they can forge
 * an assignment record that names any worker as leader.
 */

public class DistributedHerder extends AbstractHerder implements Runnable {

    // -------------------------------------------------------------------------
    // Core state variables — mixed synchronization disciplines (some volatile,
    // some synchronized, some unprotected). Inconsistent locking across readers
    // and writers opens TOCTOU windows.
    // -------------------------------------------------------------------------

    private final WorkerGroupMember member;           // Immutable after construction
    private ExtendedAssignment assignment;            // MUTABLE — updated on rebalance
    private ExtendedAssignment runningAssignment = ExtendedAssignment.empty();
    private boolean rebalanceResolved;
    private boolean canReadConfigs;

    protected ClusterConfigState configState;         // Mutable, accessed from multiple threads

    private volatile DistributedHerderRequest currentRequest;
    private volatile int generation;
    private volatile long scheduledRebalance;
    private volatile SecretKey sessionKey;            // Key used for request signing
    private volatile long keyExpiration;
    private short currentProtocolVersion;

    // -------------------------------------------------------------------------
    // isLeader() — the ONLY check before executing leader-only operations.
    // Returns true if local member ID == assignment's declared leader ID.
    // No signature, no nonce, no challenge-response.
    // -------------------------------------------------------------------------
    protected boolean isLeader() {
        // === VULNERABILITY ===
        // assignment is populated from group protocol records. If an attacker
        // can corrupt or replay these records (by writing to the internal
        // __connect-configs topic), they can set assignment.leader() to any
        // member ID they control or have observed.
        //
        // member.memberId() is the local worker's group member ID — a plain
        // String like "connect-worker-1-abc123". No cryptographic binding.
        return assignment != null && member.memberId().equals(assignment.leader());
        // === END VULNERABILITY ===
    }

    private String leaderUrl() {
        if (assignment == null)
            return null;
        return assignment.leaderUrl();  // Also derived from the unverified assignment
    }

    // -------------------------------------------------------------------------
    // All leader-only operations check isLeader() before proceeding.
    // If isLeader() returns true based on a forged assignment, any of the
    // following operations can be performed by the attacker-controlled worker:
    // -------------------------------------------------------------------------

    // Line 925: deleteConnectorConfig
    private void deleteConnectorConfig(String connName, Callback<Created<ConnectorInfo>> callback) {
        if (!isLeader()) {
            callback.onCompletion(new NotLeaderException("Not the leader", leaderUrl()), null);
            return;
        }
        // Proceeds to delete the connector config from the cluster — affects all workers
        configBackingStore.removeConnectorConfig(connName);
    }

    // Line 1266: putTaskConfigs — can reassign tasks across all workers
    private void putTaskConfigs(String connName, List<Map<String, String>> configs,
                                Callback<Void> callback, InternalRequestSignature requestSignature) {
        if (!isLeader()) {
            callback.onCompletion(new NotLeaderException("Not the leader", leaderUrl()), null);
            return;
        }
        // Malicious task configs can override all workers' task assignments
        configBackingStore.putTaskConfigs(connName, configs);
    }

    // Line 1443: restartConnector — can restart any connector across the cluster
    void restartConnector(String connName, boolean onlyFailed, boolean includeTasks,
                          Callback<ConnectorStateInfo> callback) {
        if (!isLeader()) {
            forwardToLeader(/* ... */);
            return;
        }
        // With forged leadership, attacker can restart (disrupt) any connector
    }

/*
 * EXPLOITATION CHAIN:
 *
 * Prerequisites:
 *   - WRITE ACL on internal topics: __connect-configs, __connect-offsets, __connect-status
 *   - Network access to at least one Connect worker's REST API (port 8083)
 *   - Knowledge of a target worker's group member ID (obtainable via GET /connectors metadata)
 *
 * Steps:
 *   1. Read current assignment from __connect-configs to learn the current leader ID.
 *   2. Write a crafted ConnectProtocol.Assignment record to __connect-offsets that
 *      names a worker under attacker control as the new leader.
 *   3. Trigger a rebalance (e.g., by briefly connecting/disconnecting a consumer
 *      in the Connect group) to force workers to re-read the assignment.
 *   4. Attacker's worker believes it is the leader (isLeader() returns true).
 *   5. Attacker calls PUT /connectors/{name}/config on the attacker's worker REST API.
 *   6. The worker executes leader-only config changes affecting the ENTIRE cluster.
 *
 * Impact: Full Connect cluster takeover — create, modify, delete any connector.
 */
}
