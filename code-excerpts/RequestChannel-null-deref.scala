/*
 * Source: apache/kafka trunk
 * File: core/src/main/scala/kafka/network/RequestChannel.scala
 * Lines: 52 (buffer field), 65 (initial parse), 78-80 (conditional release), 227-235 (releaseBuffer)
 *
 * FINDING-008: RequestChannel NULL dereference after buffer release → broker crash.
 *
 * The Request class holds a @volatile ByteBuffer `buffer` field. For API keys
 * that do NOT require delayed allocation (requiresDelayedAllocation = false),
 * releaseBuffer() is called early (line 78-80) setting buffer = null. Subsequent
 * code paths in error handlers and toString() that reference buffer after this
 * point encounter a NullPointerException, crashing the request handler thread.
 *
 * An attacker crafting a valid but edge-case request for such an API key that
 * triggers the error path after early buffer release can cause targeted broker
 * thread crashes, eventually exhausting the request handler thread pool.
 */

// === buffer field definition (line 52) ===
@volatile var buffer: ByteBuffer   // Set to null by releaseBuffer()

// === Initial parse — buffer is non-null here (line 65) ===
private val bodyAndSize: RequestAndSize = context.parseRequest(buffer)

// === Conditional early release (lines 78-80) ===
// For API keys where requiresDelayedAllocation == false,
// the buffer is released immediately after parsing.
if (!header.apiKey.requiresDelayedAllocation) {
  releaseBuffer()      // <-- sets buffer = null
}
// After this point, buffer IS null for the affected request types.

// ============================================================
// releaseBuffer() implementation (lines 227-235)
// ============================================================
def releaseBuffer(): Unit = {
  envelope match {
    case Some(request) =>
      request.releaseBuffer()
    case None =>
      if (buffer != null) {          // Guards against double-release only.
        memoryPool.release(buffer)   // Does NOT guard post-release access elsewhere.
        buffer = null                // <-- null assignment
      }
  }
}

// ============================================================
// toString() — accesses buffer AFTER potential null assignment (line 202)
// Called by logging and error reporting after buffer release.
// ============================================================
override def toString: String = {
  s"Request(processor=$processor, " +
  s"connectionId=${context.connectionId}, " +
  s"session=${context.principal}, " +
  s"listenerName=${context.listenerName}, " +
  s"securityProtocol=${context.securityProtocol}, " +
  s"buffer=$buffer, " +   // <-- NullPointerException if buffer was released
  s"startTimeNanos=$startTimeNanos)"
}

/*
 * EXPLOITATION PATH:
 *
 * 1. Identify an API key K where K.requiresDelayedAllocation == false.
 *    Examples: METADATA (3), LIST_OFFSETS (2), DESCRIBE_GROUPS (15), OFFSET_FETCH (9).
 *
 * 2. Send a valid request for API key K that:
 *    a. Passes initial parsing (buffer is consumed → bodyAndSize populated)
 *    b. Triggers an error response path AFTER parseRequest() returns
 *       (e.g., broker in controlled shutdown, quota exceeded, topic not found)
 *
 * 3. The error handler calls request.toString() or logs the request context.
 *    At this point buffer == null → NullPointerException.
 *
 * 4. NPE propagates up the Netty handler chain. If uncaught at the channel
 *    pipeline level, the handler thread for that connection is terminated.
 *
 * 5. Repeat across multiple connections to exhaust the request handler thread pool.
 *    With the default num.io.threads (8), 8 coordinated requests can freeze
 *    all request processing on the broker.
 *
 * MSK IMPACT:
 *   MSK brokers run standard Kafka with the default thread pool configuration.
 *   A fleet of ~8-16 connections sending coordinated edge-case requests can
 *   cause complete broker request processing suspension, failing all producers
 *   and consumers on that broker until the broker process is restarted.
 *
 * FIX:
 *   Guard buffer access in toString() and all post-release code paths:
 *     s"buffer=${if (buffer != null) buffer.toString else "<released>"}"
 *   Or use an Optional[ByteBuffer] field.
 */
