# Audit Methodology

## Scope

This research audits the Apache Kafka open-source codebase (`apache/kafka`, trunk) and the AWS MSK IAM authentication library (`aws/aws-msk-iam-auth`, main branch) for **original, previously unassigned vulnerabilities**. The focus is on code-level security flaws — not configuration mistakes or deployment anti-patterns.

Target vulnerability classes:
1. Remote Code Execution (RCE) — via broker message processing, plugin loading, or API handlers
2. RBAC / ACL privilege escalation — authorization bypass, principal confusion, DENY circumvention
3. Authentication bypass — token replay, signature validation gaps
4. Data integrity violations — false acknowledgment, silent data loss

## Approach

### Phase 1 — Attack Surface Mapping

Identified high-value components for audit:
- **Kafka Connect** (plugin classloader, REST API, distributed coordination) — high complexity, user-controlled inputs reach dangerous code paths
- **KRaft consensus layer** — distributed state machine with timing-sensitive operations
- **Client authentication** — SCRAM, OAUTHBEARER, and MSK IAM SASL mechanisms
- **Request handling pipeline** — broker's Netty-based request channel and `KafkaApis` dispatcher
- **ACL / RBAC engine** — `StandardAuthorizerData` and `StandardAuthorizer`

### Phase 2 — Code Reading

Source files were fetched directly from GitHub and read in full. Key analysis questions per component:

**For authentication code:**
- Are all JWT/token claims validated (expiry, issuer, audience, signature)?
- Is nonce generation cryptographically random and uniqueness enforced server-side?
- Are credentials zeroed after use to prevent heap exposure?

**For authorization code:**
- Does every decision point check both ALLOW and DENY ACLs without short-circuit?
- Is principal parsing resistant to injection or type confusion?
- Are wildcard principals handled correctly in both permit and deny paths?

**For request handling:**
- Are size and count fields validated before allocation?
- Are buffers guarded against use-after-free / null dereference patterns?
- Are integer arithmetic operations guarded against overflow in quota-affecting paths?

**For distributed coordination (KRaft):**
- Are state transitions atomic relative to side effects (future completions, log appends)?
- Is leader election cryptographically verified, or based solely on mutable state?
- Are epoch comparisons symmetric in PreVote vs Vote phases?

**For Connect plugin loading:**
- Is the plugin path restricted to declared directories (no symlink traversal)?
- Are loaded JARs signature-verified before execution?
- Is the REST API protected by authorization at the resource layer?

### Phase 3 — Triage

Each finding was evaluated against:
1. **Reachability** — can an external actor trigger this code path?
2. **Impact** — what is the worst-case outcome if successfully exploited?
3. **Prerequisites** — what level of access does exploitation require?
4. **Novelty** — has this specific code path been reported as a CVE previously?

### Phase 4 — PoC Development

For each confirmed finding, a minimal proof-of-concept was developed demonstrating the vulnerable condition. PoCs are located in `payloads/` and use standard tooling (kafka-python, AWS CLI, curl, bash).

## Findings Rating Methodology

CVSS v3.1 scores are estimated based on:
- **AV** (Attack Vector): Network (N) if reachable via Kafka protocol/REST; Local (L) if requires shell access
- **AC** (Attack Complexity): Low (L) if straightforward; High (H) if requires precise timing or race condition
- **PR** (Privileges Required): None (N), Low (L), or High (H) based on required Kafka permissions
- **UI** (User Interaction): None (N) in all cases (server-side vulnerabilities)
- **C/I/A** (CIA impact): Rated based on worst-case outcome of successful exploitation

All scores are marked **ESTIMATED — pending CVE assignment**.

## Responsible Disclosure Note

These findings were identified through static source code analysis. None have been tested against live Amazon MSK production infrastructure. The findings are reported here as security research. Recommended next steps:

1. Report to Apache Kafka security team: security@kafka.apache.org
2. Report MSK IAM auth findings to AWS security: aws-security@amazon.com (via https://aws.amazon.com/security/vulnerability-reporting/)
3. Allow 90-day embargo for vendor patch development before public disclosure
