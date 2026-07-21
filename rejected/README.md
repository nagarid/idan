# Rejected Findings

These two findings were removed from the confirmed-findings count after a review of each attacker's actual starting privilege. Both are retained here (not deleted) for the audit trail — they document real code defects, but neither is a self-contained finding: each assumes a precondition that nothing in this research demonstrates how to obtain, and no other finding in the set supplies it either (unlike FINDING-003, which had the same class of weakness but was rehabilitated by chaining with FINDING-004 — see `chains/CHAIN-A-connect-rest-to-rce.md`).

## FINDING-001 — MSK IAM Token Replay

Scored `PR:N` in its CVSS vector, but functionally requires the attacker to already possess a **captured/leaked valid IAM token** (sniffed traffic, log leak, compromised client). That is not "no privileges required" — it's "already had access once." No finding in this set (nor any exploit chain) provides a mechanism to intercept or exfiltrate a token, so the finding cannot be demonstrated end-to-end from a genuine zero-privilege starting point. The underlying code defect (`lifetimeMs` never validated server-side) is real and worth flagging separately as a hardening gap, but it does not stand on its own as an exploitable finding.

## FINDING-010 — DistributedHerder Leader Forgery

Scored `PR:L`, but the actual prerequisite — WRITE ACL on the internal `__connect-configs` topic — is a narrow, deliberately-restricted grant in practice, not something an ordinary authenticated Kafka principal holds by default. It is closer to `PR:H`. No other finding in this set grants that ACL, so this finding assumes the attacker already has most of the access it claims to escalate into (cluster-wide Connect control). The underlying code defect (non-cryptographic leader verification via string comparison) is real, but the finding overstates its reachability from a low-privilege starting point.

## Disposition

Both files, their code excerpts, and (for FINDING-001) its payload script are preserved unmodified under this directory. They are excluded from:
- The confirmed-findings count in the top-level `README.md` (now 8, not 10)
- The severity matrix and summary table
- The attack-chain analysis

If either finding can later be paired with a discovered token-capture or ACL-grant primitive, it should be re-promoted to `findings/` with an explicit chain reference, following the same pattern used for FINDING-003.
