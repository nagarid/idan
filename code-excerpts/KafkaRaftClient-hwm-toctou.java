/*
 * Source: apache/kafka trunk
 * File: raft/src/main/java/org/apache/kafka/raft/KafkaRaftClient.java
 * Approximate lines: 1900-1955 (onUpdateLeaderHighWatermark)
 *
 * FINDING-002: KRaft High Watermark TOCTOU — false durability guarantee.
 *
 * appendPurgatory.maybeComplete() and fetchPurgatory.completeAll() are called
 * BEFORE any re-validation of quorum membership. A demoted leader that has not
 * yet processed its own demotion will complete append futures (ACK producers)
 * for records that were never replicated to the new leader's followers.
 */

    /**
     * Called when the leader's high watermark is updated. Completes pending
     * append and fetch purgatories, then notifies listeners.
     *
     * VULNERABLE: completions happen before quorum re-check.
     */
    private void onUpdateLeaderHighWatermark(
        LeaderState<T> state,
        long currentTimeMs
    ) {
        state.highWatermark().ifPresent(highWatermark -> {
            logger.debug("Leader high watermark updated to {}", highWatermark);
            log.updateHighWatermark(highWatermark);

            // Notify add/remove voter handlers
            addVoterHandler.highWatermarkUpdated(state);
            removeVoterHandler.highWatermarkUpdated(state);

            // === VULNERABILITY: completions fire HERE ===
            // appendPurgatory holds pending acks=all produce requests.
            // If this node was demoted between the last quorum check and this
            // call, these futures represent writes that only exist on THIS node.
            appendPurgatory.maybeComplete(highWatermark.offset(), currentTimeMs);

            // All deferred fetch requests are also completed immediately.
            fetchPurgatory.completeAll(currentTimeMs);
            // === END VULNERABILITY ===

            // Listener progress notification happens last — too late to gate completions.
            updateListenersProgress(highWatermark.offset());
        });
    }

    // -------------------------------------------------------------------------
    // For comparison: the quorum leadership check used elsewhere in the class.
    // Note it is NOT invoked inside onUpdateLeaderHighWatermark before completions.
    // -------------------------------------------------------------------------

    /**
     * Validate a request which is intended for the current quorum leader.
     */
    private Optional<Errors> validateLeaderOnlyRequest(int requestEpoch) {
        if (requestEpoch < quorum.epoch()) {
            return Optional.of(Errors.FENCED_LEADER_EPOCH);
        } else if (requestEpoch > quorum.epoch()) {
            return Optional.of(Errors.UNKNOWN_LEADER_EPOCH);
        } else if (!quorum.isLeader()) {
            // Non-leaders should not receive requests matching their own epoch.
            return Optional.of(Errors.NOT_LEADER_OR_FOLLOWER);
        } else if (shutdown.get() != null) {
            return Optional.of(Errors.BROKER_NOT_AVAILABLE);
        } else {
            return Optional.empty();
        }
    }

    // -------------------------------------------------------------------------
    // appendAsLeader — called from the produce path. No post-hoc leadership
    // re-validation after the actual log.appendAsLeader() call completes.
    // -------------------------------------------------------------------------

    private LogAppendInfo appendAsLeader(Records records) {
        LogAppendInfo info = log.appendAsLeader(records, quorum.epoch());
        // TOCTOU window: leadership could be lost between the log.appendAsLeader()
        // call above and the high-watermark update that triggers onUpdateLeaderHighWatermark.
        // Producers will receive APPENDED acknowledgment even if a leader change
        // occurred and the records were never replicated.
        return info;
    }

/*
 * EXPLOITATION SCENARIO:
 *
 * 1. Attacker triggers rapid leadership churn via crafted network partitions
 *    or by injecting malformed Fetch responses that cause epoch bumps.
 *
 * 2. Node A believes it is leader at epoch E.
 *    Node A receives a Produce(acks=all) request.
 *    log.appendAsLeader() writes records to the local log.
 *
 * 3. Simultaneously, the network partition causes epoch to advance to E+1.
 *    Node B becomes leader at E+1.
 *
 * 4. Node A's high watermark update fires onUpdateLeaderHighWatermark().
 *    appendPurgatory.maybeComplete() ACKs the producer: "written, durable".
 *    BUT: Node B has no knowledge of these records.
 *
 * 5. Producer believes data is safely replicated. In reality, the records
 *    exist only on Node A's (now-follower) log. On truncation to sync with
 *    Node B's log, those records are silently discarded.
 *
 * Net result: acks=all guarantee violated, silent data loss.
 */
