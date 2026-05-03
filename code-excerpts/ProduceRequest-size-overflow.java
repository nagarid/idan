/*
 * Source: apache/kafka trunk
 * File: clients/src/main/java/org/apache/kafka/common/requests/ProduceRequest.java
 * Lines: 118-141 (partitionSizes method)
 *
 * FINDING-007: Integer overflow in ProduceRequest partition size accumulation.
 *
 * partitionSizes() accumulates record batch sizes across all topic-partitions
 * using plain Java int arithmetic. If the aggregate size of records across
 * all partitions in a single ProduceRequest exceeds Integer.MAX_VALUE (2^31-1,
 * approximately 2.1 GB), the int accumulator wraps to a negative value.
 *
 * The broker's quota enforcement reads these partition sizes to account for
 * byte-rate usage. A negative accumulated size causes quota accounting to
 * either skip the throttle check or CREDIT the client's quota, allowing
 * unbounded data production.
 */

    /**
     * Returns a map of TopicIdPartition → record batch size in bytes.
     * Used by quota enforcement to debit the producer's byte-rate quota.
     *
     * VULNERABLE: sizeInBytes() returns int. The accumulation:
     *   partitionData.records().sizeInBytes() + previousValue
     * can overflow when total > Integer.MAX_VALUE (2,147,483,647 bytes).
     *
     * After overflow, the map contains negative values. Quota code that
     * checks:  if (accumulatedBytes > quotaLimit) throttle();
     * will NEVER throttle a negative value against a positive quota limit.
     */
    Map<TopicIdPartition, Integer> partitionSizes() {
        if (partitionSizes == null) {
            synchronized (this) {
                if (partitionSizes == null) {
                    Map<TopicIdPartition, Integer> tmpPartitionSizes = new HashMap<>();
                    data.topicData().forEach(topicData ->
                        topicData.partitionData().forEach(partitionData ->
                            tmpPartitionSizes.compute(
                                new TopicIdPartition(
                                    topicData.topicId(),
                                    partitionData.index(),
                                    topicData.name()
                                ),
                                (ignored, previousValue) ->
                                    // === VULNERABILITY ===
                                    // partitionData.records().sizeInBytes() returns int.
                                    // previousValue is Integer (auto-unboxed to int).
                                    // Addition of two ints with no overflow guard.
                                    // When total > 2,147,483,647:  result wraps negative.
                                    partitionData.records().sizeInBytes() +
                                    (previousValue == null ? 0 : previousValue)
                                    // === END VULNERABILITY ===
                            )
                        )
                    );
                    partitionSizes = tmpPartitionSizes;
                }
            }
        }
        return partitionSizes;
    }

/*
 * OVERFLOW CALCULATION:
 *
 *   Integer.MAX_VALUE = 2,147,483,647 (~2.1 GB)
 *
 *   If a single ProduceRequest spans 2,200 partitions each carrying a 1 MB batch:
 *     2,200 * 1,048,576 = 2,306,867,200 bytes
 *     2,306,867,200 - 2,147,483,648 = 159,383,552  (overflowed value, still positive)
 *
 *   If spanning 2,200 partitions with 1 MB + a bit more:
 *     At some threshold the int wraps to a NEGATIVE value like -1,988,099,448
 *
 * QUOTA BYPASS PATH:
 *
 *   In KafkaApis.handleProduceRequest():
 *     val requestSize = request.sizeInBytes  // calls partitionSizes() under the hood
 *
 *   In ClientQuotaManager.recordAndGetThrottleTimeMs():
 *     if (recordedBytes > quota.bound()) return throttleTime  // skipped for negative
 *
 *   With a negative recordedBytes, the quota bound check never triggers.
 *   The producer can sustain multi-GB/s throughput ignoring all byte-rate limits.
 *
 * MSK IMPACT:
 *   Amazon MSK enforces per-client producer byte-rate quotas via MSK broker
 *   configuration. This overflow allows a single noisy neighbor to consume
 *   all broker I/O capacity and cause message processing delays for all tenants.
 *
 * FIX:
 *   Replace int with long in the accumulation:
 *     (long) partitionData.records().sizeInBytes() + (previousValue == null ? 0L : previousValue)
 *   And change the map type to Map<TopicIdPartition, Long>.
 */
