# CHAIN-A: Unauthenticated Connect REST Access → Remote Code Execution

## Metadata

| Field | Value |
|-------|-------|
| Chain ID | CHAIN-A |
| Findings Combined | [FINDING-004](../findings/FINDING-004-connect-rest-no-authz.md) (stage 1) → [FINDING-003](../findings/FINDING-003-connect-plugin-path-rce.md) (stage 2) |
| Target | `apache/kafka` (Connect runtime) |
| Components | `ConnectorsResource` (REST API), `PluginUtils` / `Plugins` (plugin classloader) |
| Category | Unauthenticated Remote Code Execution |
| Combined CVSS v3.1 Score | **9.8 CRITICAL** |
| Combined CVSS v3.1 Vector | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Combined CWE | CWE-306 (Missing Authentication) + CWE-22 (Path Traversal) + CWE-502 (Untrusted Classloading) |
| Requires Auth | **NONE** — bare network reachability to Connect REST port 8083 |
| MSK Affected | YES — MSK Connect (any deployment with default/no REST auth extension configured) |

## Why This Chain Matters

Standalone, FINDING-003 is scored `PR:L` because its stated prerequisite is "write access to the plugin directory OR a prior write primitive" — something an attacker doesn't automatically have. That precondition made FINDING-003 the weakest standalone finding in the set (see prior privilege-starting-point review).

FINDING-004 removes that precondition for free. The Connect REST API ships built-in connectors (`FileStreamSinkConnector`, `FileStreamSourceConnector`) that write/read arbitrary files on the worker's local filesystem under the worker process's own privileges — no plugin needed, no auth needed. An attacker with only network reachability to port 8083 can use this to *manufacture* the exact "prior write primitive" that FINDING-003 assumed the attacker already had.

**Net effect:** the two findings compose into unauthenticated RCE with zero prerequisites — worse than either finding's own CVSS suggests in isolation.

## Combined Attack Narrative

```
Attacker (network access to port 8083 only, zero credentials)
        │
        ▼
[Stage 1 — FINDING-004] POST /connectors
  connector.class = FileStreamSinkConnector
  file = <path reachable from plugin.path via symlink, or plugin.path itself>
        │  worker writes attacker-supplied bytes to that file/symlink target
        ▼
[Bridge] Attacker-controlled JAR now sits inside (or symlinked into) plugin.path
        │
        ▼
[Stage 2 — FINDING-003] POST /connectors
  connector.class = <attacker's malicious class name>
        │  PluginUtils.pluginUrls() walks plugin.path with FOLLOW_LINKS,
        │  picks up the planted JAR; Plugins.pluginClass() calls
        │  loader.loadClass(...) → static initializer fires
        ▼
Reverse shell as the Connect worker process
  (MSK Connect execution-role IAM permissions)
```

## Step-by-Step Exploitation

1. **Recon:** confirm reachability and default (no-auth) REST API:
   ```bash
   curl -s http://CONNECT_WORKER:8083/connector-plugins | jq .
   ```
2. **Stage 1 — plant the payload via FINDING-004** (no credentials required). Use a `FileStreamSinkConnector` reading from an internal topic the attacker also seeds, or simpler: any connector config field that lets the worker write bytes to a path under/symlinked-from `plugin.path`. In the lab PoC this is simulated directly by writing the JAR to a location reachable via symlink from `plugin.path` (see `payloads/finding-003-symlink-setup.sh`) — the REST-driven variant achieves the same file placement using only `payloads/finding-004-connect-rest-exploit.sh`'s connector-creation primitive, pointed at that path instead of `/tmp/exfil.txt`.
3. Compile the malicious connector class (`payloads/finding-003-malicious-plugin.java`) with the attacker's listener IP.
4. **Stage 2 — trigger classloading via FINDING-004** (still no credentials required):
   ```bash
   curl -X POST http://CONNECT_WORKER:8083/connectors \
     -H "Content-Type: application/json" \
     -d '{"name":"init","config":{"connector.class":"MaliciousConnector","tasks.max":"1","topics":"x"}}'
   ```
5. `Plugins.pluginClass()` → `loader.loadClass("MaliciousConnector")` → static initializer executes → reverse shell connects back.
6. Shell runs as the Connect worker process — on MSK Connect, this carries the attached execution role's IAM permissions (frequently `kafka-cluster:*` plus any S3/other grants).

## Combined CVSS Justification

FINDING-003 alone is scored `PR:L` (8.8) because it assumes the attacker already has filesystem write access. FINDING-004 supplies that access with `PR:N`. Recomputing FINDING-003's impact (`C:H/I:H/A:H`, unchanged — it's still full RCE) at the privilege level the chain actually requires (`PR:N`, since stage 1 needs no credentials) yields the same vector as FINDING-004 itself:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
ISS = 1 - [(1-0.56)(1-0.56)(1-0.56)] = 0.9148
Impact = 6.42 * 0.9148 = 5.873
Exploitability = 8.22 * 0.85(AV:N) * 0.77(AC:L) * 0.85(PR:N) * 0.85(UI:N) = 3.887
Score = Roundup(min(5.873 + 3.887, 10)) = Roundup(9.760) = 9.8 CRITICAL
```

The chain doesn't just add impact — it proves FINDING-004's existing 9.8 rating already implicitly includes reachable RCE, since 004 alone can be used to manufacture 003's precondition.

## Amazon MSK Specific Impact

- Same execution-role blast radius as FINDING-003/004 individually, but reachable with **zero** prerequisites instead of requiring prior filesystem access.
- MSK Connect's data-plane REST calls are not CloudTrail-logged (see FINDING-004 detection notes), so both stages of this chain are invisible to AWS-side audit logging — only VPC Flow Logs and worker-local logs would show it.
- A single VPC-reachable position (no IAM credentials, no Kafka principal, no SASL token) is sufficient for full worker compromise.

## Proposed Fix

Fixing either stage breaks the chain:
1. **Stage 1 (FINDING-004):** require authentication on the Connect REST API (`rest.extension.classes=...BasicAuthSecurityRestExtension` or an IAM-aware proxy) — see FINDING-004's fix.
2. **Stage 2 (FINDING-003):** validate canonical paths post-symlink-resolution and require JAR signing — see FINDING-003's fix.

Fixing only one stage still leaves the other finding's standalone risk in place; both should be remediated independently, not just the chain.

## Detection

- VPC Flow Logs: connections to port 8083 from unexpected sources, followed by outbound connections from the worker to unexpected external IPs (reverse shell callback)
- Worker filesystem monitoring: `inotify`/`auditd` on `plugin.path` catching writes or symlink creation shortly before a new `connector.class` referencing an unrecognized class name
- Correlate two connector-creation events on the same worker in a short window: one writing to a filesystem path, one instantiating a previously-unseen `connector.class`
