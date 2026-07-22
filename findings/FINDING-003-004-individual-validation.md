# Individual Validation: FINDING-003 and FINDING-004

## Metadata

| Field | Value |
|-------|-------|
| Scope | FINDING-003 and FINDING-004, tested **independently of each other** (see `CHAIN-A-validation.md` for why they cannot be composed as originally claimed) |
| Verdict | **Both CONFIRMED** — live RCE and live unauthenticated RBAC bypass reproduced against real `apache/kafka` 4.3.1 binaries |
| Method | Same lab pattern as `CHAIN-A-validation.md`: native Kafka 4.3.1 KRaft broker + Connect distributed worker, fresh clean state |

Each finding is granted only its own stated prerequisite — FINDING-004 gets nothing but network reachability; FINDING-003 is granted a pre-existing filesystem write primitive into `plugin.path` (its own documented precondition, not anything supplied by FINDING-004).

## FINDING-004 — Unauthenticated Connect REST API: CONFIRMED

All requests below carry no `Authorization` header and no credentials of any kind.

| Step | Request | Result |
|---|---|---|
| List connectors | `GET /connectors` | `200 OK` — `[]` |
| Create connector | `POST /connectors` (`FileStreamSinkConnector`, topic `customer-pii` → `/tmp/exfil-demo.txt`) | `201 Created` |
| Read back full config | `GET /connectors/production-etl/config` | `200 OK` — full config returned, including any embedded secrets |
| Check status | `GET /connectors/production-etl/status` | `200 OK` — `RUNNING` |
| Pause (offset-manipulation precursor) | `PUT /connectors/production-etl/pause` | `202 Accepted` |
| Destroy pipeline | `DELETE /connectors/production-etl` | `204 No Content` |
| Confirm destroyed | `GET /connectors` | `200 OK` — `[]` |

Every one of the three scenarios described in the original finding (data-exfil connector creation, pipeline destruction, offset/state manipulation) succeeded with zero authentication, exactly as claimed. **FINDING-004 stands fully confirmed, 9.8 CRITICAL, independent of any chain.**

## FINDING-003 — Plugin-path symlink traversal → RCE: CONFIRMED

Setup (simulating the finding's own stated prerequisite — the attacker already has *some* filesystem write primitive, however obtained; this test does not use FINDING-004 to supply it):

1. Compiled a real `SourceConnector` subclass (`MaliciousConnector.java`, this directory) whose static initializer runs `id`, `hostname`, `date` via `Runtime.exec` and writes the output to `/tmp/RCE_PROOF_FINDING003.txt` — proof of arbitrary OS command execution, without needing a live reverse-shell listener for this validation.
2. Packaged it into a JAR and placed it **outside** `plugin.path` (`.../outside_plugin_path/MaliciousConnector.jar`).
3. Created a symlink from inside the declared `plugin.path` to that external JAR:
   ```
   .../plugins/kafka-extra-plugin.jar -> .../outside_plugin_path/MaliciousConnector.jar
   ```
4. Restarted the Connect worker (plugin discovery is scan-at-startup only — see `CHAIN-A-validation.md` Finding 3).

**Result**, before any `POST /connectors` call was made:
```
RCE PROOF: static initializer executed as uid=0(root) gid=0(root) groups=0(root) on vm at Wed Jul 22 11:42:07 UTC 2026
```
`/connector-plugins` also confirmed the symlinked class was picked up and catalogued as `MaliciousConnector`, sourced through the plugin-path symlink to a JAR that physically resides outside the declared plugin directory — the exact symlink-escape mechanism FINDING-003 describes.

Also completed the documented REST trigger step for completeness (`POST /connectors` with `connector.class: MaliciousConnector` → connector created and reached `RUNNING` state), matching the finding's own step-by-step exploitation section.

**FINDING-003 stands fully confirmed** — arbitrary code execution as the worker process, via a symlink escaping the declared `plugin.path`, given its own stated prerequisite (pre-existing write access to `plugin.path` or a location reachable via symlink from it). This is unaffected by the CHAIN-A blockers, which only concern whether FINDING-004 can *supply* that prerequisite for free — it cannot, but FINDING-003 was never contingent on FINDING-004 to begin with.

## Net assessment

| Finding | Status | Notes |
|---|---|---|
| FINDING-004 | **Confirmed**, 9.8 CRITICAL | Fully reproduced live, zero auth, all documented scenarios |
| FINDING-003 | **Confirmed**, 8.8 HIGH | Fully reproduced live, given its own stated precondition (pre-existing write primitive) |
| CHAIN-A (composition) | **Not reproducible** | See `CHAIN-A-validation.md` — the specific mechanism claimed to link them does not work |

Both findings should be reported and remediated independently, each at its own already-assigned severity. Neither depends on the other being true.

## Artifacts

- `lab/finding-003-004-individual-validation/MaliciousConnector.java` — real `SourceConnector` payload used for this test (command-execution proof via marker file instead of a live reverse shell).
