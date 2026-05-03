/*
 * Source: apache/kafka trunk
 * File: connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/resources/ConnectorsResource.java
 * Total lines: 407
 *
 * FINDING-004: Kafka Connect REST API — zero per-endpoint authorization.
 *
 * None of the JAX-RS resource methods carry @RolesAllowed, @DenyAll, @PermitAll,
 * or any security annotation. There is no authorization filter registered in
 * the RestServer setup. Authorization is entirely delegated to the Herder
 * implementation, which only guards LEADER-only operations (connector creation,
 * config updates, deletion) — not read operations, and not cross-worker paths.
 *
 * Any client that can reach port 8083 (the Connect REST port) can invoke ALL
 * endpoints without any credential check at the REST layer.
 */

package org.apache.kafka.connect.runtime.rest.resources;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
// NOTE: NO import for javax.annotation.security.RolesAllowed
// NOTE: NO import for javax.ws.rs.container.ContainerRequestFilter (auth filter)

@Path("/connectors")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ConnectorsResource {

    private final Herder herder;
    private final HerderRequestHandler requestHandler;
    private boolean isTopicTrackingDisabled;
    private boolean isTopicTrackingResetDisabled;

    // -------------------------------------------------------------------------
    // CREATE — no @RolesAllowed, no auth check
    // -------------------------------------------------------------------------
    @POST
    // Missing: @RolesAllowed({"admin", "connector-admin"})
    public Response createConnector(
            @QueryParam("forward") Boolean forward,
            ConnectorInfo info) throws Throwable {
        // Validation only checks that name in URL matches name in body.
        // No authentication. No RBAC check. Any caller proceeds.
        checkAndPutConnectorConfigName(info.name(), info.config());
        return requestHandler.completeOrForwardRequest(
            cb -> herder.putConnectorConfig(info.name(), info.config(), false, cb),
            forward, new TypeReference<ConnectorInfo>() {}
        );
    }

    // -------------------------------------------------------------------------
    // DELETE — no @RolesAllowed, no auth check
    // -------------------------------------------------------------------------
    @DELETE
    @Path("/{connector}")
    // Missing: @RolesAllowed({"admin", "connector-admin"})
    public void destroyConnector(
            @PathParam("connector") String connector,
            @QueryParam("forward") Boolean forward) throws Throwable {
        requestHandler.completeOrForwardRequest(
            cb -> herder.deleteConnectorConfig(connector, cb),
            forward, new TypeReference<Herder.Created<ConnectorInfo>>() {}
        );
    }

    // -------------------------------------------------------------------------
    // UPDATE CONFIG — no @RolesAllowed, no auth check
    // -------------------------------------------------------------------------
    @PUT
    @Path("/{connector}/config")
    // Missing: @RolesAllowed({"admin", "connector-admin"})
    public Response putConnectorConfig(
            @PathParam("connector") String connector,
            @QueryParam("forward") Boolean forward,
            Map<String, String> connectorConfig) throws Throwable {
        checkAndPutConnectorConfigName(connector, connectorConfig);
        return requestHandler.completeOrForwardRequest(
            cb -> herder.putConnectorConfig(connector, connectorConfig, true, cb),
            forward, new TypeReference<ConnectorInfo>() {}
        );
    }

    // -------------------------------------------------------------------------
    // PAUSE — no @RolesAllowed, no auth check
    // -------------------------------------------------------------------------
    @PUT
    @Path("/{connector}/pause")
    // Missing: @RolesAllowed({"admin", "operator"})
    public Response pauseConnector(@PathParam("connector") String connector) {
        herder.pauseConnector(connector);
        return Response.accepted().build();
    }

    // -------------------------------------------------------------------------
    // ALTER OFFSETS — no @RolesAllowed, no auth check
    // -------------------------------------------------------------------------
    @PATCH
    @Path("/{connector}/offsets")
    // Missing: @RolesAllowed({"admin"})
    public Response alterConnectorOffsets(
            @PathParam("connector") String connector,
            @QueryParam("forward") Boolean forward,
            ConnectorOffsets offsets) throws Throwable {
        return requestHandler.completeOrForwardRequest(
            cb -> herder.alterConnectorOffsets(connector, offsets.toMap(), cb),
            forward, new TypeReference<Message>() {}
        );
    }

    // -------------------------------------------------------------------------
    // Connector name validation — checks body/URL match only, no authz
    // -------------------------------------------------------------------------
    private void checkAndPutConnectorConfigName(
            String connectorName, Map<String, String> connectorConfig) {
        String existingName = connectorConfig.get(ConnectorConfig.NAME_CONFIG);
        if (existingName != null && !existingName.equals(connectorName)) {
            throw new BadRequestException(
                "Connector name configuration (" + existingName +
                ") doesn't match connector name in the URL (" + connectorName + ")");
        }
        connectorConfig.put(ConnectorConfig.NAME_CONFIG, connectorName);
    }

    /*
     * IMPACT ON MSK CONNECT:
     *
     * MSK Connect workers run inside AWS-managed VPCs. The Connect REST API
     * (port 8083) is accessible to any resource in the same VPC security group.
     * Lambda functions, ECS tasks, and EC2 instances in the same subnet can
     * reach the endpoint without any credential.
     *
     * An attacker with VPC network access can:
     *   1. POST /connectors with a FileStreamSinkConnector targeting sensitive topics
     *      → read all messages from payment/PII topics to an attacker-controlled S3 bucket
     *   2. DELETE /connectors/critical-pipeline
     *      → destroy production data pipelines without any authentication
     *   3. PATCH /connectors/billing-connector/offsets
     *      → replay historical transactions by resetting consumer offsets
     */
}
