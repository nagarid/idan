# CHAIN-A Validation Report: Unauthenticated Connect REST Access → RCE

## Metadata

| Field | Value |
|-------|-------|
| Subject | CHAIN-A (FINDING-004 → FINDING-003 composition) |
| Verdict | **NOT REPRODUCIBLE as described — two independent blockers confirmed empirically** |
| Method | Live lab, real `apache/kafka` 4.3.1 binaries (KRaft broker + Connect distributed worker), not simulated |
| Individual findings | FINDING-003 and FINDING-004 remain independently valid (verified separately against `apache/kafka` trunk source) |
| Combined chain | Does not execute end-to-end via the unauthenticated REST-only path the chain document claims |

## Summary

CHAIN-A claims that FINDING-004 (unauthenticated Connect REST API) supplies, "for free," the filesystem-write precondition that FINDING-003 (plugin-path symlink traversal → RCE) requires — yielding zero-prerequisite unauthenticated RCE via two `POST /connectors` calls. This was tested end-to-end in a real lab rather than accepted on paper. The chain does not hold: the specific mechanism it names (`FileStreamSinkConnector` writing a JAR into `plugin.path`) cannot produce a working JAR under any Connect converter configuration, and the classloading trigger described for stage 2 does not work as claimed either — it requires a worker process restart which the unauthenticated REST surface cannot cause.

Both underlying component findings (FINDING-003, FINDING-004) hold up as separately reported when checked against `apache/kafka` trunk source (see prior validation notes). This report addresses only the *composition* claim.

## Lab

- Kafka 4.3.1 (`kafka_2.13-4.3.1`), downloaded directly from `downloads.apache.org` — official release binary, not a container image (Docker Hub's CDN is blocked by this environment's egress policy; the tarball path is the reliable substitute for `lab/docker-compose.yml`-style container labs here).
- Single-node KRaft broker (`kafka-storage.sh format` + `kafka-server-start.sh`), PLAINTEXT `localhost:9092`.
- Connect distributed worker (`connect-distributed.sh`), REST on `localhost:8083`, `plugin.path` pointed at a directory **owned by the same OS user the worker runs as** — the most charitable case for the attacker (real deployments are frequently more restrictive, e.g. read-only mounts).
- Attacker-side raw producer: `RawProduce.java` (this directory) — a minimal Kafka producer using `ByteArraySerializer` to push exact JAR bytes into a topic, standing in for "however the attacker gets bytes into Kafka."
- Probe payload: `ProbeConnector.java` (this directory) — a real `SourceConnector` subclass whose static initializer writes a marker file (`/tmp/RCE_PROVEN_MARKER`) instead of opening a reverse shell. This proves code execution without requiring live C2 infrastructure for a validation exercise.

## Finding 1 — Stock Apache Kafka excludes `connect-file*.jar` from the runtime classpath by default

`bin/kafka-run-class.sh` (line 36 in the 4.3.1 release) hardcodes:

```
regex="(-(test|test-sources|src|scaladoc|javadoc)\.jar|jar.asc|connect-file.*\.jar)$"
```

`connect-file.*\.jar` — the package containing `FileStreamSinkConnector`/`FileStreamSourceConnector` — is explicitly filtered out of every classpath-construction loop in the launch script.

**Empirical confirmation:** on a freshly started worker with a stock `plugin.path`, `GET /connector-plugins` returned only the three Mirror* connectors:

```json
[
  {"class": "org.apache.kafka.connect.mirror.MirrorCheckpointConnector", ...},
  {"class": "org.apache.kafka.connect.mirror.MirrorHeartbeatConnector", ...},
  {"class": "org.apache.kafka.connect.mirror.MirrorSourceConnector", ...}
]
```

`FileStreamSinkConnector` is absent. A `POST /connectors` request naming it fails with `400: Failed to find any class that implements Connector`.

**Implication:** the chain's stage 1 primitive is only available if an operator has *deliberately* copied `connect-file-*.jar` into `plugin.path` — an additional deployment choice CHAIN-A never lists as a prerequisite. (Whether AWS's MSK Connect worker image bundles this jar by default is unverified — flagged as an open question for anyone with access to a real MSK Connect worker.)

## Finding 2 — `FileStreamSinkConnector` cannot write a valid binary JAR under any converter configuration

Charitably assuming Finding 1 is satisfied (jar manually added to `plugin.path`), the actual byte-write mechanism was tested against a real compiled JAR (`Probe.jar`, 706 bytes, valid ZIP/JAR structure, sha256-verified).

`FileStreamSinkTask.put()` (real source, `connect/file/.../FileStreamSinkTask.java`) does:
```java
outputStream.println(record.value());
```
This is `PrintStream.println(Object)` → `String.valueOf(x)` → `Object#toString()`. Not a raw byte write.

| `value.converter` | Output file | Byte-identical to source? | Usable as a JAR? |
|---|---|---|---|
| `org.apache.kafka.connect.converters.ByteArrayConverter` | 12 bytes: `[B@5027e805` | No — Java's default array `toString()`, not the array's contents | No |
| `org.apache.kafka.connect.storage.StringConverter` | 1031 bytes (source was 706) | No — lossy UTF-8 round-trip corrupts non-UTF8-safe bytes | No — `jar tf` fails: `java.util.zip.ZipException: zip END header not found` |

No combination of stock converters produces a working JAR. This is a hard, mechanism-level blocker independent of `plugin.path` permissions, symlinks, or any other deployment factor — it fails even under the most permissive filesystem assumptions.

## Finding 3 — Stage 2 does not trigger on a REST call; it requires a worker process restart

Isolated stage 2 independently (manually placing `ProbeConnector.jar` behind a symlink from `plugin.path`, bypassing the broken stage 1 to test this half on its own):

- **While the worker was already running:** planting the symlink, then `POST /connectors` with `connector.class=ProbeConnector` → `400: Failed to find any class that implements Connector` (the class wasn't in the plugin catalog built at startup). No live rescan-on-request exists.
- **After restarting the worker process:** `ProbeConnector` appeared in `/connector-plugins`, and — critically — `/tmp/RCE_PROVEN_MARKER` already existed **before any `POST /connectors` call was made**, confirming the static initializer fires during the plugin-*discovery scan at worker startup*, not in response to a connector-creation request as CHAIN-A's diagram states.

**Implication:** the chain's "Stage 2 — trigger classloading" step (a second unauthenticated `POST /connectors`) is not actually the trigger, and more importantly, execution is gated on a **worker process restart** occurring after the plant. Nothing in the documented, unauthenticated Connect REST API (individual connector/task restart endpoints included) causes a full worker JVM restart. An attacker limited to the REST surface described in FINDING-004 has no way to force this.

## Corrected prerequisite list for CHAIN-A to function end-to-end

All of the following must hold simultaneously; none is supplied by FINDING-004 alone:

1. Network reachability to the Connect REST port, no credentials — **confirmed real** (FINDING-004 stands).
2. `plugin.path` includes a connector capable of a **lossless raw byte write** to an attacker-chosen path — stock `FileStreamSinkConnector` fails this (Finding 2). Requires a non-stock/custom connector or an unidentified alternate write primitive.
3. The write-capable connector's target path lands inside `plugin.path`, or inside a location a **pre-existing** symlink from `plugin.path` already points to — a filesystem-permission fact about the specific deployment, not something the REST primitive grants.
4. The written bytes reconstruct a byte-exact, structurally valid JAR.
5. The planted class is assignable to `Connector` (or another scanned plugin interface) — confirmed the scanner enforces this before instantiation.
6. **A Connect worker process restart occurs** after the plant and before the attacker needs the result — not triggerable via the documented unauthenticated REST API.

## Recommendation

Treat CHAIN-A as **unconfirmed as a zero-prerequisite, REST-only exploit chain**. FINDING-003 and FINDING-004 should continue to be reported and remediated as independent findings (both check out against real source). The composed 9.8 CVSS chain narrative should not be published or relied upon without either (a) identifying an actual working raw-byte-write primitive in some real deployment's plugin set, and (b) accounting for the worker-restart gating condition on stage 2.

## Artifacts

- `lab/chain-a-validation/RawProduce.java` — minimal raw-bytes Kafka producer used to test converter fidelity.
- `lab/chain-a-validation/ProbeConnector.java` — benign `Connector` subclass with a static-initializer marker, used to test the classloading/restart-timing question without live C2 infrastructure.
