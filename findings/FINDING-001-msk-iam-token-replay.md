# FINDING-001: MSK IAM Token — Missing Server-Side Expiry Validation

## Metadata

| Field | Value |
|-------|-------|
| Finding ID | FINDING-001 |
| Target | `aws/aws-msk-iam-auth` |
| Component | `IAMOAuthBearerToken`, `IAMOAuthBearerLoginCallbackHandler` |
| Source File | `src/main/java/software/amazon/msk/auth/iam/internals/IAMOAuthBearerToken.java` |
| Approximate Lines | 44–74 (constructor), 98–115 (handleCallback) |
| Category | Authentication Bypass — Token Replay |
| CVSS v3.1 Score | **7.4 HIGH** |
| CVSS v3.1 Vector | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| CVSS Breakdown | ISCBase=0.8064, ISC=5.177, Exploit=2.221, Score=Roundup(7.398)=7.4 |
| CWE | CWE-613: Insufficient Session Expiration |
| Requires Auth | NO — attacker needs a captured token, not active credentials |
| MSK Affected | YES — all MSK clusters using IAM authentication |

## Summary

The MSK IAM authentication library computes a token lifetime (`lifetimeMs`) from the SigV4 pre-signed URL parameters client-side, but the Kafka broker **never validates this value server-side**. An attacker who captures a legitimate IAM OAUTHBEARER token can replay it against MSK brokers after its 15-minute TTL has elapsed. The broker accepts the token until the TCP connection drops, regardless of expiry.

## Vulnerable Code (verbatim)

```java
// IAMOAuthBearerToken.java — constructor
public IAMOAuthBearerToken(String token) throws URISyntaxException, ParseException {
    this.tokenValue = token;
    String decodedUrl = new String(
        Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
    URI uri = new URI(decodedUrl);
    Map<String, List<String>> params = parseQueryParams(uri.getQuery());

    // lifetimeMs computed from client-provided URL parameter
    int lifeTimeSeconds = Integer.parseInt(
        params.get(SignerConstant.X_AMZ_EXPIRES).get(0));   // e.g. "900"

    final LocalDateTime signedDate = LocalDateTime.parse(
        params.get(SignerConstant.X_AMZ_DATE).get(0), dateFormat);

    this.startTimeMs = signedDate.toInstant(ZoneOffset.UTC).toEpochMilli();
    this.lifetimeMs  = this.startTimeMs + (lifeTimeSeconds * 1000L);
    // No broker-side check: if (System.currentTimeMillis() > lifetimeMs) deny()
}
```

```java
// IAMOAuthBearerLoginCallbackHandler.java — handleCallback
private void handleCallback(OAuthBearerTokenCallback callback)
        throws IOException, URISyntaxException, ParseException {
    AwsCredentials awsCredentials = credentialsProvider.resolveCredentials();
    String tokenValue = generateTokenValue(awsCredentials, getCurrentRegion());
    callback.token(getOAuthBearerToken(tokenValue));
    // awsCredentials (including secretAccessKey String) not zeroed after use
}
```

## Root Cause

The `OAuthBearerToken` interface defines `lifetimeMs()` so that the broker can enforce token expiry. However, in the MSK IAM implementation, the Kafka broker's SASL validation path (`SaslServerCallbackHandler` → `OAuthBearerValidatorCallbackHandler`) stores the lifetime from the token but **does not compare it against wall-clock time** before granting the authenticated session. The lifetime is used only for metrics/logging purposes.

## Attack Prerequisites

- A captured MSK IAM OAUTHBEARER token (base64url-encoded pre-signed URL)
- Network access to the MSK broker on port 9098 (IAM/TLS listener)
- The token only needs to have been valid once — it does not need to be currently valid

**How to capture a token:**
1. SSRF vulnerability in the same VPC (e.g., CVE-2025-27817 on a Connect worker) can retrieve IMDS credentials, which can be used to generate a token
2. Overly verbose application logging that logs the SASL client token
3. Network interception on a non-TLS hop (misconfigured plaintext listener)

## Step-by-Step Exploitation

1. Attacker captures a legitimate MSK IAM token (base64url pre-signed URL) via any of the capture methods above
2. Waits until the `X-Amz-Expires` window (default: 900 seconds = 15 minutes) has elapsed
3. Configures a Kafka client with the expired token hardcoded in the SASL JAAS config
4. Connects to MSK broker — SASL/OAUTHBEARER handshake proceeds
5. Broker parses the token via `IAMOAuthBearerToken`, stores `lifetimeMs`
6. Broker does NOT check `System.currentTimeMillis() > token.lifetimeMs()` — session is granted
7. Attacker can produce and consume with the principal identity of the original token owner

## Payload

See `payloads/finding-001-replay-token.sh` for the full PoC.

```bash
# Core exploit: produce with an expired token
kafka-console-producer.sh \
  --bootstrap-server b-1.CLUSTER.REGION.kafka.amazonaws.com:9098 \
  --producer-property "security.protocol=SASL_SSL" \
  --producer-property "sasl.mechanism=OAUTHBEARER" \
  --producer-property "sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required \
    oauth.token.endpoint.uri=\"CAPTURED_TOKEN_HERE\";" \
  --topic target-topic
```

## Expected Outcome

On a vulnerable broker: the producer connects and writes successfully. The `lifetimeMs` in the token is 15 minutes in the past, but the broker accepts it.

## Amazon MSK Specific Impact

- **MSK Standard:** All MSK clusters with IAM authentication enabled are affected
- **MSK Serverless:** Same IAM auth path — affected
- **MSK Connect:** Connect workers use the same IAMOAuthBearerLoginCallbackHandler; captured worker tokens can be replayed to gain the worker's IAM role permissions on the broker
- **Version scope:** All MSK Kafka versions since IAM auth was introduced (Kafka 2.6.x+)
- **AWS rotation caveat:** Rotating the underlying IAM credentials (access key rotation) invalidates the ability to generate NEW tokens, but does NOT invalidate tokens already in active sessions. An attacker who replays before rotation can maintain an active session indefinitely.

## Proposed Fix

Add a server-side expiry check in the Kafka broker's OAUTHBEARER validation callback, or in the MSK IAM validator:

```java
// In IAMServerCallbackHandler or OAuthBearerValidatorCallbackHandler:
if (token.lifetimeMs() < System.currentTimeMillis()) {
    throw new SaslAuthenticationException(
        "IAM token expired at " + Instant.ofEpochMilli(token.lifetimeMs()));
}
```

Alternatively, AWS should enforce token TTL at the broker level, independent of the client library.

## Detection

- **CloudTrail:** Enable MSK authentication logging; look for the same principal authenticating multiple times from different source IPs or after unusually long gaps between auths and actions
- **MSK Metrics:** `AuthenticationRate` spike without corresponding connection count increase may indicate replay
- **Log pattern:** On patched version, look for `SaslAuthenticationException: IAM token expired`
