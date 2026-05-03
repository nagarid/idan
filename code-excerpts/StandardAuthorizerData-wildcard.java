/*
 * Source: apache/kafka trunk
 * File: metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerData.java
 * Approximate lines: 280-330 (authorize), 400-420 (matchingPrincipals), 480-540 (findResult)
 *
 * FINDING-006: ACL DENY bypass via wildcard principal matching asymmetry.
 *
 * matchingPrincipals() always returns BOTH the specific session principal AND
 * WILDCARD_KAFKA_PRINCIPAL ("User:*"). The findAclRule() method iterates ACLs
 * and returns on the first DENY match — but only if the ACL's kafkaPrincipal
 * is in the matchingPrincipals set.
 *
 * The issue: if an admin sets DENY User:* on a resource, the intent is to
 * deny ALL users. But the findAclRule() implementation processes ACLs ordered
 * by resource specificity and may evaluate a specific ALLOW for "User:alice"
 * BEFORE evaluating the wildcard DENY for "User:*", depending on the internal
 * ACL ordering. If findAclRule() short-circuits on the first ALLOW without
 * completing all DENY checks, the wildcard DENY is never applied.
 */

package org.apache.kafka.metadata.authorizer;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;

import java.net.InetAddress;
import java.util.Set;

import static org.apache.kafka.common.acl.AclPermissionType.ALLOW;
import static org.apache.kafka.server.authorizer.AuthorizationResult.ALLOWED;
import static org.apache.kafka.server.authorizer.AuthorizationResult.DENIED;

public class StandardAuthorizerData {

    // The wildcard principal that matches ALL users
    static final KafkaPrincipal WILDCARD_KAFKA_PRINCIPAL =
        new KafkaPrincipal(KafkaPrincipal.USER_TYPE, "*");

    // -------------------------------------------------------------------------
    // authorize() — main entry point. Calls findAclRule() with the set of
    // matching principals (specific + wildcard).
    // -------------------------------------------------------------------------
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
            // matchingPrincipals returns {alice, User:*}
            // findAclRule iterates ACL entries for the resource
            MatchingRule rule = findAclRule(
                matchingPrincipals(requestContext),   // <-- always includes WILDCARD
                requestContext.clientAddress().getHostAddress(),
                action
            );
            logAuditMessage(principal, requestContext, action, rule);
            return rule.result();
        }
    }

    // -------------------------------------------------------------------------
    // matchingPrincipals() — always includes WILDCARD_KAFKA_PRINCIPAL.
    // The returned set is used to match ACL entries.
    // -------------------------------------------------------------------------
    static Set<KafkaPrincipal> matchingPrincipals(AuthorizableRequestContext context) {
        KafkaPrincipal sessionPrincipal = context.principal();
        KafkaPrincipal basePrincipal = sessionPrincipal.getClass().equals(KafkaPrincipal.class)
            ? sessionPrincipal
            : new KafkaPrincipal(sessionPrincipal.getPrincipalType(), sessionPrincipal.getName());
        // Both the specific principal AND the wildcard are included.
        // This means any ACL matching EITHER will be considered.
        return Set.of(basePrincipal, WILDCARD_KAFKA_PRINCIPAL);  // <-- WILDCARD always present
    }

    // -------------------------------------------------------------------------
    // findResult() — evaluates a single ACL entry against the principal set.
    // Returns ALLOWED or DENIED if the ACL matches, null otherwise.
    // -------------------------------------------------------------------------
    static AuthorizationResult findResult(
        Action action,
        Set<KafkaPrincipal> matchingPrincipals,
        String host,
        StandardAcl acl
    ) {
        // Step 1: Does the ACL's principal match any of the session principals?
        if (!matchingPrincipals.contains(acl.kafkaPrincipal())) {
            return null;  // not applicable
        }
        // Step 2: Host check
        if (!acl.host().equals("*") && !acl.host().equals(host)) {
            return null;
        }
        // Step 3: Operation check
        if (acl.operation() != AclOperation.ALL) {
            if (acl.permissionType().equals(ALLOW)) {
                // For ALLOW, DESCRIBE/DESCRIBE_CONFIGS are implied by broader ops
                switch (action.operation()) {
                    case DESCRIBE:
                        if (!IMPLIES_DESCRIBE.contains(acl.operation())) return null;
                        break;
                    case DESCRIBE_CONFIGS:
                        if (!IMPLIES_DESCRIBE_CONFIGS.contains(acl.operation())) return null;
                        break;
                    default:
                        if (action.operation() != acl.operation()) return null;
                        break;
                }
            } else if (action.operation() != acl.operation()) {
                return null;
            }
        }
        return acl.permissionType().equals(ALLOW) ? ALLOWED : DENIED;
    }

    // -------------------------------------------------------------------------
    // findAclRule() — iterates resource-specific ACLs.
    // The traversal order (LITERAL before PREFIXED before WILDCARD resources)
    // means a LITERAL ALLOW for "User:alice" on "topic:sensitive" is evaluated
    // BEFORE a WILDCARD DENY for "User:*" on "topic:*" in some code paths,
    // depending on how ACLs are stored in the TrieBasedAclStore.
    // The DENY-first guarantee holds only within the same resource scope;
    // cross-scope ordering may permit ALLOW to win over a broader-scope DENY.
    // -------------------------------------------------------------------------
}

/*
 * BYPASS SCENARIO:
 *
 * Admin sets:
 *   DENY  User:*     WRITE  Topic:sensitive   (wildcard subject deny)
 *   ALLOW User:alice WRITE  Topic:sensitive   (specific allow, added later)
 *
 * In some ACL store implementations, LITERAL+specific-principal entries are
 * checked before LITERAL+wildcard-principal entries. When findAclRule() finds
 * the ALLOW for User:alice first and the traversal does not continue to check
 * DENY entries, alice is granted WRITE despite the explicit wildcard DENY.
 *
 * Test command to verify:
 *   kafka-acls.sh --add --deny-principal User:* --operation Write --topic sensitive
 *   kafka-acls.sh --add --allow-principal User:alice --operation Write --topic sensitive
 *   kafka-console-producer.sh --producer.config alice.properties --topic sensitive
 *   # If the write succeeds → DENY bypass confirmed
 */
