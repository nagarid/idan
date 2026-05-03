# Amazon MSK Vulnerability Research

**Original security research via source code analysis of `apache/kafka` and `aws/aws-msk-iam-auth`.**

All findings are novel — discovered through direct code reading, not derived from existing CVE databases. No CVE IDs are assigned yet. Responsible disclosure recommended before publication.

---

## Executive Summary

A source code audit of Apache Kafka trunk and the AWS MSK IAM authentication library identified **10 original vulnerability findings** spanning Remote Code Execution, RBAC/ACL bypass, authentication replay, data integrity violations, and denial of service. Several findings chain together for amplified impact in MSK Connect deployments.

| ID | Title | Category | CVSS Est. | MSK Impact |
|----|-------|----------|-----------|------------|
| [FINDING-001](#finding-001) | MSK IAM Token — Missing Server-Side Expiry | Auth Bypass | **7.5 HIGH** | All MSK IAM clusters |
| [FINDING-002](#finding-002) | KRaft HWM TOCTOU — False Durability | Data Integrity | **8.1 HIGH** | MSK Standard (KRaft) |
| [FINDING-003](#finding-003) | Connect Plugin Symlink → RCE | RCE | **8.8 HIGH** | MSK Connect |
| [FINDING-004](#finding-004) | Connect REST API — No Authorization | RBAC Bypass | **9.1 CRITICAL** | MSK Connect |
| [FINDING-005](#finding-005) | KRaft Epoch Asymmetry — Split-Brain | Consensus Bypass | **7.5 HIGH** | MSK Standard (KRaft) |
| [FINDING-006](#finding-006) | ACL Wildcard DENY Bypass | RBAC Bypass | **7.5 HIGH** | MSK + StandardAuthorizer |
| [FINDING-007](#finding-007) | ProduceRequest Int Overflow → Quota Bypass | Privilege Escalation | **7.5 HIGH** | All MSK clusters |
| [FINDING-008](#finding-008) | RequestChannel NULL Deref → Broker Crash | Remote DoS | **7.5 HIGH** | All MSK clusters |
| [FINDING-009](#finding-009) | MSK IAM — No Auth Rate Limiting → DoS Amp | Denial of Service | **6.5 MEDIUM** | All MSK IAM clusters |
| [FINDING-010](#finding-010) | DistributedHerder Non-Crypto Leader → Takeover | RBAC Bypass | **8.8 HIGH** | MSK Connect |

---

## Severity Matrix

```
CRITICAL (9.0+)  ████████████████████  FINDING-004 (9.1)
HIGH     (7.0+)  ██████████████████    FINDING-003 (8.8), FINDING-010 (8.8)
                 ████████████████      FINDING-002 (8.1)
                 █████████████         FINDING-001, FINDING-005, FINDING-006, FINDING-007, FINDING-008 (7.5)
MEDIUM   (4.0+)  ████████              FINDING-009 (6.5)
```

---

## Repository Structure

```
.
├── README.md                          ← This file
├── METHODOLOGY.md                     ← Audit approach and rating methodology
├── REFERENCES.md                      ← Source files, NVD links, MITRE ATT&CK mapping
├── findings/
│   ├── FINDING-001-msk-iam-token-replay.md
│   ├── FINDING-002-kraft-hwm-toctou.md
│   ├── FINDING-003-connect-plugin-path-rce.md
│   ├── FINDING-004-connect-rest-no-authz.md
│   ├── FINDING-005-kraft-epoch-splitbrain.md
│   ├── FINDING-006-acl-wildcard-deny-bypass.md
│   ├── FINDING-007-produce-int-overflow-quota.md
│   ├── FINDING-008-requestchannel-null-deref.md
│   ├── FINDING-009-msk-iam-no-ratelimit.md
│   └── FINDING-010-connect-herder-leader.md
├── code-excerpts/                     ← Verbatim vulnerable code from source
│   ├── IAMOAuthBearerToken-lifetimeMs.java
│   ├── KafkaRaftClient-hwm-toctou.java
│   ├── PluginUtils-symlink-traversal.java
│   ├── Plugins-unsafe-classloader.java
│   ├── ConnectorsResource-no-authz.java
│   ├── KafkaRaftClient-epoch-asymmetry.java
│   ├── StandardAuthorizerData-wildcard.java
│   ├── ProduceRequest-size-overflow.java
│   ├── RequestChannel-null-deref.scala
│   ├── IAMCallbackHandler-no-ratelimit.java
│   └── DistributedHerder-leader-check.java
├── payloads/                          ← PoC code (for authorized lab use only)
│   ├── finding-001-replay-token.sh
│   ├── finding-003-malicious-plugin.java
│   ├── finding-003-symlink-setup.sh
│   ├── finding-004-connect-rest-exploit.sh
│   ├── finding-005-vote-epoch-craft.py
│   ├── finding-006-acl-deny-bypass.sh
│   ├── finding-007-produce-overflow.py
│   └── finding-008-null-deref-request.py
└── deploy-yamls/                      ← Lab infrastructure configs
    ├── msk-connect-vulnerable-worker.yaml
    ├── kafka-connect-distributed.properties
    └── kraft-cluster-config.yaml
```

---

## Finding Summaries

### FINDING-001
**MSK IAM Token — Missing Server-Side Expiry Validation**
- Source: `aws/aws-msk-iam-auth` — `IAMOAuthBearerToken.java:44-74`
- The `lifetimeMs` calculated from SigV4 `X-Amz-Expires` is never validated server-side. Captured tokens can be replayed past their 15-minute TTL.
- [Full analysis →](findings/FINDING-001-msk-iam-token-replay.md)

### FINDING-002
**KRaft High Watermark TOCTOU — False Durability Guarantee**
- Source: `apache/kafka` — `KafkaRaftClient.java` `onUpdateLeaderHighWatermark`
- `acks=all` produce requests are confirmed before quorum leadership is re-validated. Demoted leaders silently ACK writes that the new leader never received.
- [Full analysis →](findings/FINDING-002-kraft-hwm-toctou.md)

### FINDING-003
**Kafka Connect Plugin Loading — Symlink Traversal → RCE**
- Source: `apache/kafka` — `PluginUtils.java`, `Plugins.java`
- `Files.walkFileTree(FOLLOW_LINKS)` follows symlinks outside the declared `plugin.path`. No JAR signature verification. Static initializers execute at classloading time.
- [Full analysis →](findings/FINDING-003-connect-plugin-path-rce.md)

### FINDING-004
**Kafka Connect REST API — Missing Per-Endpoint Authorization**
- Source: `apache/kafka` — `ConnectorsResource.java`
- Zero `@RolesAllowed` annotations on 20 REST endpoints. No authentication layer by default. Any VPC-reachable client can create/delete/modify connectors without credentials.
- [Full analysis →](findings/FINDING-004-connect-rest-no-authz.md)

### FINDING-005
**KRaft Epoch Asymmetry — Split-Brain Leadership**
- Source: `apache/kafka` — `KafkaRaftClient.java`
- `PreVote` uses `>` while `Vote` uses `>=` for epoch validation. At `lastEpoch == replicaEpoch`, PreVote passes but Vote fails — two nodes can simultaneously win pre-election and proceed to split-brain.
- [Full analysis →](findings/FINDING-005-kraft-epoch-splitbrain.md)

### FINDING-006
**ACL Wildcard DENY Bypass via Principal Matching Asymmetry**
- Source: `apache/kafka` — `StandardAuthorizerData.java` `matchingPrincipals()`
- `matchingPrincipals()` always includes `WILDCARD_KAFKA_PRINCIPAL`. If ACL traversal finds a specific ALLOW before completing DENY checks for the wildcard, the DENY is skipped — violating the documented DENY-wins guarantee.
- [Full analysis →](findings/FINDING-006-acl-wildcard-deny-bypass.md)

### FINDING-007
**ProduceRequest Integer Overflow → Quota Bypass**
- Source: `apache/kafka` — `ProduceRequest.java:118-141`
- `partitionSizes()` accumulates batch sizes as Java `int`. At >2.1 GB aggregate, the int wraps negative — quota enforcement never fires, allowing unbounded throughput.
- [Full analysis →](findings/FINDING-007-produce-int-overflow-quota.md)

### FINDING-008
**RequestChannel NULL Dereference → Broker Crash**
- Source: `apache/kafka` — `RequestChannel.scala`
- `releaseBuffer()` sets `buffer = null` for non-delayed-allocation API keys. Subsequent `toString()` calls in error paths dereference the null buffer — NPE crashes request handler threads.
- [Full analysis →](findings/FINDING-008-requestchannel-null-deref.md)

### FINDING-009
**MSK IAM — No Auth Rate Limiting → DoS Amplification**
- Source: `aws/aws-msk-iam-auth` — `IAMOAuthBearerLoginCallbackHandler.java`
- No rate limiter, credential cache, or circuit breaker on `resolveCredentials()`. A connection flood amplifies into IMDS/STS rate-limit exhaustion — blocking all client authentication.
- [Full analysis →](findings/FINDING-009-msk-iam-no-ratelimit.md)

### FINDING-010
**DistributedHerder Non-Cryptographic Leader Verification → Cluster Takeover**
- Source: `apache/kafka` — `DistributedHerder.java:1721`
- `isLeader()` uses string equality on member IDs read from unverified Kafka topic records. A forged assignment record grants attacker-controlled workers cluster-wide leadership authority.
- [Full analysis →](findings/FINDING-010-connect-herder-leader.md)

---

## Attack Chains

### Chain A — MSK Connect Full Compromise (FINDING-004 → FINDING-003)
1. Reach Connect REST API on port 8083 (no auth — FINDING-004)
2. Create a connector pointing to an attacker-controlled class name
3. If plugin directory contains a matching symlink (FINDING-003), classloading triggers a reverse shell
4. Code executes as the MSK Connect execution IAM role

### Chain B — IAM Token Exfiltration + Replay (FINDING-004 → FINDING-001)
1. Via unauth REST API (FINDING-004), create a FileStreamSink connector that writes all messages from sensitive topics to `/tmp/`
2. Read those messages to find application-level AWS tokens or MSK IAM tokens in transit
3. Replay captured MSK IAM token past TTL (FINDING-001) to maintain persistent broker access

### Chain C — Connect Leader Takeover + Pipeline Destruction (FINDING-010 → FINDING-004)
1. Write forged assignment to `__connect-configs` (FINDING-010)
2. Attacker worker becomes "leader"
3. Via now-authorized leader operations + unauth REST (FINDING-004): delete all production connectors

---

## Responsible Disclosure

These findings were identified through static source code analysis only. No production AWS MSK infrastructure was tested.

**Report to:**
- Apache Kafka: security@kafka.apache.org
- AWS MSK IAM Auth: https://aws.amazon.com/security/vulnerability-reporting/
- Recommended embargo: 90 days from initial report

---

## Lab Setup

```bash
# Start the 3-node KRaft lab cluster
cd deploy-yamls/
docker compose -f kraft-cluster-config.yaml up -d

# Run logic-level PoCs (no broker needed)
python3 payloads/finding-005-vote-epoch-craft.py       # epoch asymmetry proof
python3 payloads/finding-007-produce-overflow.py       # int overflow proof

# Run network-level PoCs (against lab broker)
python3 payloads/finding-008-null-deref-request.py localhost 19092
bash payloads/finding-006-acl-deny-bypass.sh localhost:19092 ...

# Test Connect findings (against lab Connect worker)
bash payloads/finding-004-connect-rest-exploit.sh http://localhost:8083
```

---

*Research conducted May 2025. Source code from `apache/kafka` trunk and `aws/aws-msk-iam-auth` main branch.*
