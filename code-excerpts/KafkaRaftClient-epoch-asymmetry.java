/*
 * Source: apache/kafka trunk
 * File: raft/src/main/java/org/apache/kafka/raft/KafkaRaftClient.java
 *
 * FINDING-005: KRaft epoch validation asymmetry between PreVote and Vote.
 *
 * The boolean isIllegalEpoch is computed with different operators depending
 * on whether this is a PreVote or a standard Vote:
 *   - PreVote:      lastEpoch >  replicaEpoch  (strict greater-than)
 *   - Standard Vote: lastEpoch >= replicaEpoch  (greater-than-or-equal)
 *
 * This asymmetry means there exists a window where lastEpoch == replicaEpoch
 * passes the PreVote check but FAILS the Vote check. A node that wins a
 * PreVote at epoch E (where lastEpoch == E) may then fail its own Vote
 * at that epoch, resulting in inconsistent candidate promotion across the
 * cluster and potential split-brain leadership.
 */

    /**
     * Handle an inbound Vote or PreVote request.
     * Called from the poll loop after message dispatch.
     *
     * @param preVote  true if this is a PreVote request, false for standard Vote
     */
    private VoteResponseData handleVoteRequest(
        RaftRequest.Inbound requestMetadata,
        boolean preVote
    ) {
        VoteRequestData request = (VoteRequestData) requestMetadata.data();
        int replicaEpoch   = request.candidateEpoch();
        int replicaId      = request.candidateId();
        int lastEpoch      = request.lastOffsetEpoch();
        long lastEpochEndOffset = request.lastOffset();

        // === VULNERABILITY: asymmetric epoch comparison ===
        //
        // For PreVote  (preVote == true):
        //   isIllegalEpoch = lastEpoch > replicaEpoch
        //   => lastEpoch == replicaEpoch is ALLOWED (not illegal)
        //
        // For Vote (preVote == false):
        //   isIllegalEpoch = lastEpoch >= replicaEpoch
        //   => lastEpoch == replicaEpoch is ILLEGAL
        //
        // Scenario:
        //   A prospective node has lastEpoch = E, replicaEpoch = E.
        //   PreVote check: E > E = false  → not illegal → PreVote SUCCEEDS.
        //   Actual Vote check: E >= E = true → ILLEGAL → Vote REJECTED.
        //
        // This creates a window where a node wins pre-election consensus but
        // then cannot win the actual election. Under adversarial timing
        // (crafted messages that push lastEpoch == replicaEpoch at the boundary),
        // two nodes may simultaneously believe they hold pre-vote majorities
        // and both attempt leader election in the same epoch.
        boolean isIllegalEpoch = preVote ? lastEpoch > replicaEpoch
                                         : lastEpoch >= replicaEpoch;
        // === END VULNERABILITY ===

        if (isIllegalEpoch) {
            return buildVoteResponse(Errors.INVALID_REQUEST, false);
        }

        // Epoch validation against local state
        Optional<Errors> errorOpt = validateVoterOnlyRequest(replicaEpoch);
        if (errorOpt.isPresent()) {
            return buildVoteResponse(errorOpt.get(), false);
        }
        // ...continues with log offset comparison and vote grant decision
    }

    /*
     * EXPLOITATION:
     *
     * 1. Attacker controls or monitors network traffic between KRaft nodes.
     *
     * 2. Attacker delays Vote Request messages from node A (legitimate leader
     *    candidate at epoch E) until a new epoch E' = E+1 is triggered
     *    on another node B by a separate partition event.
     *
     * 3. Node A's PreVote at epoch E is accepted by a quorum (E > E-1, passes
     *    for PreVote where E-1 < E).
     *
     * 4. Node B has advanced to epoch E+1. Node B's PreVote at E+1 also
     *    passes (lastEpoch = E, replicaEpoch = E+1, check: E > E+1 = false).
     *
     * 5. Both A and B proceed to standard Vote phase simultaneously.
     *    Depending on timing, both can accumulate votes from different
     *    partitioned subsets of the quorum.
     *
     * 6. Both declare themselves leaders for different epochs. When the
     *    network heals, one side's committed records are discarded — silent
     *    data loss with valid producer acknowledgments on both sides.
     */
