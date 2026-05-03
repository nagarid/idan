/*
 * Source: apache/kafka trunk
 * File: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginUtils.java
 * Approximate lines: 190-280 (pluginLocations, pluginUrls, pluginSources)
 *
 * FINDING-003 (part 1): Plugin path traversal via symlink following.
 *
 * pluginLocations() resolves each path via Paths.get().toAbsolutePath() which
 * normalizes ".." sequences, but does NOT follow symlinks and compare the
 * resolved target against the declared plugin root. An attacker who can write
 * a symlink inside the declared plugin directory can point it to any JAR on
 * the filesystem.
 *
 * pluginUrls() then calls Files.walk() which follows symlinks by default
 * (FileVisitOption.FOLLOW_LINKS is the implicit default on most JVM versions).
 */

package org.apache.kafka.connect.runtime.isolation;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

public class PluginUtils {

    // Comma-separated paths from worker config "plugin.path"
    private static final String COMMA_WITH_WHITESPACE = "\\s*,\\s*";

    /**
     * Parse and resolve plugin locations from the config string.
     *
     * VULNERABLE: toAbsolutePath() normalizes path separators but does NOT
     * prevent symlink targets from escaping the declared directory.
     */
    public static Set<Path> pluginLocations(String pluginPath, boolean failFast) {
        Set<Path> locations = new LinkedHashSet<>();
        if (pluginPath == null || pluginPath.trim().isEmpty()) {
            return locations;
        }
        for (String path : pluginPath.split(COMMA_WITH_WHITESPACE)) {
            if (path.isEmpty()) continue;
            // toAbsolutePath() resolves relative segments (../), but symlinks
            // that resolve to paths OUTSIDE this directory are NOT detected.
            Path location = Paths.get(path).toAbsolutePath();  // <-- no symlink check
            if (!Files.isDirectory(location)) {
                if (failFast) {
                    throw new ConnectException("Invalid plugin.path entry: " + location);
                }
                continue;
            }
            locations.add(location);
        }
        return locations;
    }

    /**
     * Walk a plugin location directory and collect all JAR and ZIP archives.
     *
     * VULNERABLE: Files.walk() follows symbolic links by default. Any symlink
     * inside /opt/kafka/plugins/ that points to /tmp/malicious.jar will be
     * included in the returned list without any boundary check.
     */
    public static List<Path> pluginUrls(Path topPath) throws IOException {
        final List<Path> urls = new ArrayList<>();
        Files.walkFileTree(topPath, EnumSet.of(FileVisitOption.FOLLOW_LINKS),
            Integer.MAX_VALUE, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (isArchive(file)) {
                        urls.add(file);  // <-- symlink target is added here without
                                         //     checking if it escapes topPath
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        return urls;
    }

    public static boolean isArchive(Path path) {
        String lower = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return lower.endsWith(".jar") || lower.endsWith(".zip");
    }

    public static boolean isClassFile(Path path) {
        return path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".class");
    }

    /*
     * ATTACK PATH:
     *
     *   # As any user with write access to /opt/kafka/plugins/:
     *   $ ln -s /tmp/MaliciousConnector.jar /opt/kafka/plugins/evil.jar
     *
     *   # /tmp/MaliciousConnector.jar is outside the declared plugin directory,
     *   # but pluginUrls() follows the symlink and includes it.
     *   # pluginSources() wraps it in a URLClassLoader — see Plugins.java.
     *   # When createConnector("com.attacker.MaliciousConnector") is called,
     *   # the static initializer block executes immediately.
     */
}
