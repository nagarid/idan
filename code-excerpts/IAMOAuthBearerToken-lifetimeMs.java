/*
 * Source: aws/aws-msk-iam-auth
 * File: src/main/java/software/amazon/msk/auth/iam/internals/IAMOAuthBearerToken.java
 *
 * FINDING-001: Missing server-side expiry validation on MSK IAM OAuth tokens.
 *
 * The constructor calculates lifetimeMs and startTimeMs from the SigV4
 * X-Amz-Expires and X-Amz-Date URL parameters. These values are exposed
 * via the OAuthBearerToken interface. However, the Kafka broker's
 * OAuthBearerValidatorCallback and StandardAuthorizer never compare
 * lifetimeMs() against System.currentTimeMillis() before granting access.
 * The TTL is purely informational — it is never enforced server-side.
 */

package software.amazon.msk.auth.iam.internals;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class IAMOAuthBearerToken implements OAuthBearerToken {

    private static final SimpleDateFormat dateFormat =
        new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");

    private static final String KAFKA_SERVICE = "kafka";

    private final String tokenValue;
    private final long startTimeMs;
    private final long lifetimeMs;        // <-- CALCULATED from URL params, never enforced server-side
    private final String principalName;

    public IAMOAuthBearerToken(String token) throws URISyntaxException, ParseException {
        this.tokenValue = token;

        // Decode the base64url-encoded pre-signed URL
        String decodedUrl = new String(
            Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);

        URI uri = new URI(decodedUrl);
        Map<String, List<String>> params = parseQueryParams(uri.getQuery());

        // === VULNERABILITY START ===
        // lifetimeMs is derived from X-Amz-Expires in the pre-signed URL.
        // This value is CLIENT-PROVIDED and never re-validated by the broker.
        // An attacker replaying a captured token can never be rejected on TTL grounds.
        int lifeTimeSeconds = Integer.parseInt(
            params.get(SignerConstant.X_AMZ_EXPIRES).get(0));      // e.g. "900" (15 min)

        final LocalDateTime signedDate = LocalDateTime.parse(
            params.get(SignerConstant.X_AMZ_DATE).get(0), dateFormat);

        this.startTimeMs = signedDate.toInstant(ZoneOffset.UTC).toEpochMilli();
        this.lifetimeMs  = this.startTimeMs + (lifeTimeSeconds * 1000L);
        // === VULNERABILITY END ===
        // Nothing in the broker validates: if (System.currentTimeMillis() > lifetimeMs) deny()

        // Principal name extracted from X-Amz-Security-Token / caller identity
        this.principalName = extractPrincipalName(params);
    }

    @Override
    public String value() {
        return tokenValue;
    }

    @Override
    public Set<String> scope() {
        return Collections.emptySet();
    }

    @Override
    public long lifetimeMs() {
        // Returns the pre-computed expiry timestamp — never checked server-side
        return lifetimeMs;
    }

    @Override
    public String principalName() {
        return principalName;
    }

    @Override
    public Long startTimeMs() {
        return startTimeMs;
    }

    // --- helper stubs ---

    private Map<String, List<String>> parseQueryParams(String query) {
        if (query == null) return Collections.emptyMap();
        Map<String, List<String>> result = new HashMap<>();
        Arrays.stream(query.split("&"))
            .forEach(pair -> {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2) {
                    result.computeIfAbsent(kv[0], k -> new java.util.ArrayList<>()).add(kv[1]);
                }
            });
        return result;
    }

    private String extractPrincipalName(Map<String, List<String>> params) {
        // Derived from SigV4 signing identity — not re-verified by broker
        return params.getOrDefault("X-Amz-SignedHeaders",
            Collections.singletonList("unknown")).get(0);
    }
}

/*
 * BROKER-SIDE GAP — for reference, the relevant broker code path:
 *
 * In Kafka's OAuthBearerLoginModule / SaslServerCallbackHandler, after the
 * client presents its token, the broker calls:
 *
 *   OAuthBearerValidatorCallbackHandler.handle(callbacks)
 *
 * For the MSK IAM mechanism, this delegates to IAMServerCallbackHandler which
 * calls IAMOAuthBearerToken to parse the token. The token's lifetimeMs() value
 * is stored in the authenticated session, but there is NO check of the form:
 *
 *   if (token.lifetimeMs() < System.currentTimeMillis()) {
 *       throw new SaslException("Token expired");
 *   }
 *
 * before the session is granted. The token lives until the TCP connection drops.
 */
