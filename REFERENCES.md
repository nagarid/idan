# References

## Source Files Audited

### apache/kafka (trunk — commit audited May 2025)

| File | GitHub Path |
|------|-------------|
| KafkaRaftClient.java | `raft/src/main/java/org/apache/kafka/raft/KafkaRaftClient.java` |
| StandardAuthorizerData.java | `metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerData.java` |
| StandardAuthorizer.java | `metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java` |
| PluginUtils.java | `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginUtils.java` |
| Plugins.java | `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/Plugins.java` |
| ConnectorsResource.java | `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/resources/ConnectorsResource.java` |
| DistributedHerder.java | `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/distributed/DistributedHerder.java` |
| ProduceRequest.java | `clients/src/main/java/org/apache/kafka/common/requests/ProduceRequest.java` |
| RequestChannel.scala | `core/src/main/scala/kafka/network/RequestChannel.scala` |
| KafkaApis.scala | `core/src/main/scala/kafka/server/KafkaApis.scala` |

### aws/aws-msk-iam-auth (main — audited May 2025)

| File | GitHub Path |
|------|-------------|
| IAMOAuthBearerLoginCallbackHandler.java | `src/main/java/software/amazon/msk/auth/iam/IAMOAuthBearerLoginCallbackHandler.java` |
| IAMOAuthBearerToken.java | `src/main/java/software/amazon/msk/auth/iam/internals/IAMOAuthBearerToken.java` |
| IAMSaslClient.java | `src/main/java/software/amazon/msk/auth/iam/IAMSaslClient.java` |
| MSKCredentialProvider.java | `src/main/java/software/amazon/msk/auth/iam/internals/MSKCredentialProvider.java` |

---

## Apache Kafka Security Resources

- Apache Kafka CVE List: https://kafka.apache.org/cve-list.html
- Apache Kafka Security Documentation: https://kafka.apache.org/documentation/#security
- Kafka Improvement Proposals (KIPs): https://cwiki.apache.org/confluence/display/KAFKA/Kafka+Improvement+Proposals

## AWS MSK Security Resources

- Amazon MSK Security Documentation: https://docs.aws.amazon.com/msk/latest/developerguide/security.html
- AWS MSK IAM Auth Library: https://github.com/aws/aws-msk-iam-auth
- AWS Security Hub MSK Controls: https://docs.aws.amazon.com/securityhub/latest/userguide/msk-controls.html
- Amazon MSK Supported Versions: https://docs.aws.amazon.com/msk/latest/developerguide/supported-kafka-versions.html
- AWS Security Bulletins: https://aws.amazon.com/security/security-bulletins/

## MITRE ATT&CK Mapping

| Finding | Tactic | Technique | Sub-technique |
|---------|--------|-----------|---------------|
| FINDING-001 | Credential Access | T1550 — Use Alternate Authentication Material | T1550.001 — Application Access Token |
| FINDING-002 | Impact | T1490 — Inhibit System Recovery | — |
| FINDING-003 | Execution | T1059 — Command and Scripting Interpreter | T1059.007 — JavaScript (via classloader) |
| FINDING-003 | Persistence | T1574 — Hijack Execution Flow | T1574.006 — Dynamic Linker Hijacking |
| FINDING-004 | Collection | T1530 — Data from Cloud Storage | — |
| FINDING-004 | Privilege Escalation | T1078 — Valid Accounts | T1078.004 — Cloud Accounts |
| FINDING-005 | Impact | T1499 — Endpoint Denial of Service | T1499.004 — Application Exhaustion Flood |
| FINDING-006 | Privilege Escalation | T1548 — Abuse Elevation Control Mechanism | — |
| FINDING-007 | Defense Evasion | T1562 — Impair Defenses | T1562.001 — Disable or Modify Tools |
| FINDING-008 | Impact | T1499 — Endpoint Denial of Service | T1499.003 — Application Exhaustion Flood |
| FINDING-009 | Impact | T1499 — Endpoint Denial of Service | — |
| FINDING-010 | Privilege Escalation | T1548 — Abuse Elevation Control Mechanism | — |

## CWE References

| CWE | Name | Used In |
|-----|------|---------|
| CWE-613 | Insufficient Session Expiration | FINDING-001 |
| CWE-367 | Time-of-check Time-of-use (TOCTOU) Race Condition | FINDING-002 |
| CWE-22 | Path Traversal | FINDING-003 |
| CWE-284 | Improper Access Control | FINDING-004 |
| CWE-362 | Race Condition | FINDING-005 |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | FINDING-006 |
| CWE-190 | Integer Overflow or Wraparound | FINDING-007 |
| CWE-476 | NULL Pointer Dereference | FINDING-008 |
| CWE-400 | Uncontrolled Resource Consumption | FINDING-009 |
| CWE-306 | Missing Authentication for Critical Function | FINDING-010 |

## Tools Referenced

- [kafka-python](https://github.com/dpkp/kafka-python) — Python Kafka client used in PoC scripts
- [ysoserial](https://github.com/frohoff/ysoserial) — Java deserialization payload generator
- [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit) — JNDI exploit framework
- [AWS CLI](https://aws.amazon.com/cli/) — Used for MSK cluster interaction
