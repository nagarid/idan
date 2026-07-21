# Amazon MSK Vulnerability Research

**Original security research via source code analysis of `apache/kafka` and `aws/aws-msk-iam-auth`.**

All findings are novel — discovered through direct code reading, not derived from existing CVE databases. No CVE IDs are assigned yet. Responsible disclosure recommended before publication.

---

## Executive Summary

A source code audit of Apache Kafka trunk and the AWS MSK IAM authentication library identified **8 confirmed vulnerability findings** spanning Remote Code Execution, RBAC/ACL bypass, data integrity violations, and denial of service. Two additional candidate findings were reviewed and rejected (see `rejected/`) because each assumed a privileged starting point that nothing in this research demonstrates how to obtain. Two of the confirmed findings chain together for materially higher severity than either scores alone — see [Attack Chains](#attack-chains).

| ID | Title | Category | CVSS v3.1 | MSK Impact |
|----|-------|----------|-----------|------------|
| [FINDING-002](#finding-002) | KRaft HWM TOCTOU — False Durability | Data Integrity | **7.4 HIGH** | MSK Standard (KRaft) |
| [FINDING-003](#finding-003) | Connect Plugin Symlink → RCE | RCE | **8.8 HIGH** | MSK Connect |
| [FINDING-004](#finding-004) | Connect REST API — No Authorization | RBAC Bypass | **9.8 CRITICAL** | MSK Connect |
| [FINDING-005](#finding-005) | KRaft Epoch Asymmetry — Split-Brain | Consensus Bypass | **7.4 HIGH** | MSK Standard (KRaft) |
| [FINDING-006](#finding-006) | ACL Wildcard DENY Bypass | RBAC Bypass | **8.1 HIGH** | MSK + StandardAuthorizer |
| [FINDING-007](#finding-007) | ProduceRequest Int Overflow → Quota Bypass | Privilege Escalation | **7.1 HIGH** | All MSK clusters |
| [FINDING-008](#finding-008) | RequestChannel NULL Deref → Broker Crash | Remote DoS | **7.5 HIGH** | All MSK clusters |
| [FINDING-009](#finding-009) | MSK IAM — No Auth Rate Limiting → DoS Amp | Denial of Service | **7.5 HIGH** | All MSK IAM clusters |

| Chain ID | Findings Combined | Combined CVSS v3.1 |
|----------|--------------------|-----------------|
| [CHAIN-A](chains/CHAIN-A-connect-rest-to-rce.md) | FINDING-004 → FINDING-003 | **9.8 CRITICAL** |
| [CHAIN-B](chains/CHAIN-B-epoch-splitbrain-to-hwm-toctou.md) | FINDING-005 → FINDING-002 | **9.1 CRITICAL** |

**Rejected:** FINDING-001 (IAM token replay), FINDING-010 (DistributedHerder leader forgery) — moved to `rejected/`, see rationale there.

---

## Severity Matrix

```
CRITICAL (9.0+)  ████████████████████  FINDING-004 (9.8), CHAIN-A (9.8), CHAIN-B (9.1)
HIGH     (7.0+)  ██████████████████    FINDING-003 (8.8)
                 ████████████████      FINDING-006 (8.1)
                 █████████████         FINDING-008 (7.5), FINDING-009 (7.5)
                 ████████████          FINDING-002 (7.4), FINDING-005 (7.4)
                 ███████████           FINDING-007 (7.1)
```

---

## Repository Structure

```
.
├── README.md                          ← This file
├── METHODOLOGY.md                     ← Audit approach and rating methodology
├── REFERENCES.md                      ← Source files, NVD links, MITRE ATT&CK mapping
├── findings/
│   ├── FINDING-002-kraft-hwm-toctou.md
│   ├── FINDING-003-connect-plugin-path-rce.md
│   ├── FINDING-004-connect-rest-no-authz.md
│   ├── FINDING-005-kraft-epoch-splitbrain.md
│   ├── FINDING-006-acl-wildcard-deny-bypass.md
│   ├── FINDING-007-produce-int-overflow-quota.md
│   ├── FINDING-008-requestchannel-null-deref.md
│   └── FINDING-009-msk-iam-no-ratelimit.md
├── chains/                            ← Multi-finding attack chains (full reports)
│   ├── CHAIN-A-connect-rest-to-rce.md
│   └── CHAIN-B-epoch-splitbrain-to-hwm-toctou.md
├── rejected/                          ← Findings removed from the confirmed set, with rationale
│   ├── README.md
│   ├── FINDING-001-msk-iam-token-replay.md
│   ├── FINDING-010-connect-herder-leader.md
│   ├── code-excerpts/
│   └── payloads/
├── code-excerpts/                     ← Verbatim vulnerable code from source
│   ├── KafkaRaftClient-hwm-toctou.java
│   ├── PluginUtils-symlink-traversal.java
│   ├── Plugins-unsafe-classloader.java
│   ├── ConnectorsResource-no-authz.java
│   ├── KafkaRaftClient-epoch-asymmetry.java
│   ├── StandardAuthorizerData-wildcard.java
│   ├── ProduceRequest-size-overflow.java
│   ├── RequestChannel-null-deref.scala
│   └── IAMCallbackHandler-no-ratelimit.java
├── payloads/                          ← PoC code (for authorized lab use only)
│   ├── finding-003-malicious-plugin.java
│   ├── finding-003-symlink-setup.sh
│   ├── finding-004-connect-rest-exploit.sh
│   ├── finding-005-vote-epoch-craft.py
│   ├── finding-006-acl-deny-bypass.sh
│   ├── finding-007-produce-overflow.py
│   └── finding-008-null-deref-request.py
├── lab/                                ← Live Kafka 4.2.0 (KRaft) Docker lab + FINDING-007 live PoC
│   ├── docker-compose.yml
│   └── poc_007_live.py
└── deploy-yamls/                      ← Lab infrastructure configs
    ├── msk-connect-vulnerable-worker.yaml
    ├── kafka-connect-distributed.properties
    └── kraft-cluster-config.yaml
```

---

## Finding Summaries

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

---

## Attack Chains

Two confirmed findings compose into materially higher-severity chains than either scores alone. Full reports (metadata, combined CVSS derivation, step-by-step exploitation, detection) live in `chains/`.

### CHAIN-A — Unauthenticated Connect REST Access → RCE (FINDING-004 → FINDING-003)
FINDING-003's RCE standalone requires the attacker to already have filesystem write access to `plugin.path`. FINDING-004's unauthenticated REST API supplies that access for free via a built-in `FileStreamSinkConnector`, then triggers the classloading RCE — full unauthenticated RCE with zero prerequisites.
**Combined CVSS: 9.8 CRITICAL** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
[Full report →](chains/CHAIN-A-connect-rest-to-rce.md)

### CHAIN-B — Epoch Asymmetry → HWM TOCTOU (FINDING-005 → FINDING-002)
FINDING-002's false-durability TOCTOU only fires during a naturally-occurring demotion race (`AC:H`). FINDING-005's PreVote/Vote epoch asymmetry lets an attacker manufacture that exact race on demand, dropping attack complexity to Low.
**Combined CVSS: 9.1 CRITICAL** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`) — up from 7.4 HIGH for either finding alone.
[Full report →](chains/CHAIN-B-epoch-splitbrain-to-hwm-toctou.md)

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
