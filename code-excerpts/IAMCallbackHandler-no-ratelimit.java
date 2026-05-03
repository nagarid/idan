/*
 * Source: aws/aws-msk-iam-auth
 * File: src/main/java/software/amazon/msk/auth/iam/IAMOAuthBearerLoginCallbackHandler.java
 *
 * FINDING-009: MSK IAM — no rate limiting on credential resolution or auth failures.
 *
 * The handleCallback() method resolves AWS credentials synchronously via
 * credentialsProvider.resolveCredentials(). There is no retry cap, no
 * exponential backoff on SdkException, and no rate limit on how quickly
 * successive authentication requests can invoke this method.
 *
 * Under adversarial conditions, a flood of concurrent connection attempts
 * (all failing authentication) causes unbounded parallel credential resolution
 * calls to the EC2 Instance Metadata Service (IMDS) or STS. This exhausts
 * IMDS connection quotas and IAM STS rate limits, creating a compute
 * amplification DoS on both the MSK broker and the AWS IAM service.
 */

    /**
     * Handle SASL callback — resolves AWS credentials and generates a token.
     *
     * VULNERABLE: No rate limiting, no backoff, no connection cap.
     * Each failed auth attempt triggers a full credential resolution cycle.
     */
    private void handleCallback(OAuthBearerTokenCallback callback)
            throws IOException, URISyntaxException, ParseException {
        if (callback.token() != null) {
            throw new IllegalArgumentException("Callback had a token already");
        }

        // === VULNERABILITY ===
        // resolveCredentials() makes an HTTP call to IMDS (if running on EC2/ECS)
        // or STS (if using assumed roles). There is no:
        //   - Rate limiting (calls per second cap)
        //   - Backoff on repeated failures
        //   - Circuit breaker for IMDS/STS unavailability
        //   - Throttle on concurrent auth attempts
        AwsCredentials awsCredentials = credentialsProvider.resolveCredentials();
        // === END VULNERABILITY ===

        String tokenValue = generateTokenValue(awsCredentials, getCurrentRegion());
        callback.token(getOAuthBearerToken(tokenValue));
        // Credentials are NOT zeroed after use — remain in heap until GC
    }

    /**
     * Generate the base64-encoded pre-signed URL token from AWS credentials.
     *
     * NOTE: awsCredentials object (containing secretAccessKey) is passed around
     * and never explicitly cleared. AWS SDK AwsCredentials objects are immutable
     * String-backed — the secret key string cannot be zeroed by the caller.
     */
    private String generateTokenValue(AwsCredentials awsCredentials, Region region) {
        // awsCredentials.secretAccessKey() is a plain String — permanently in heap
        // until GC collects it (no guarantee of timing).
        final AuthenticationRequestParams params = AuthenticationRequestParams
            .create(getHostName(region), awsCredentials, UserAgentUtils.getUserAgentValue());
        final SdkHttpFullRequest signedRequest = aws4Signer.presignRequest(params);
        String signedUrl = signedRequest.toBuilder()
            .appendRawQueryParameter("User-Agent", UserAgentUtils.getUserAgentValue())
            .build().getUri().toString();
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(signedUrl.getBytes(StandardCharsets.UTF_8));
    }

/*
 * AMPLIFICATION SCENARIO:
 *
 * AWS IMDS rate limits (as of 2024):
 *   - Default hop limit: 1 (single-hop, prevents SSRF from containers)
 *   - PUT token endpoint: ~100 requests/second before throttling
 *   - STS AssumeRole: ~100 requests/second per IAM entity
 *
 * Attack:
 *   1. Attacker opens 500 concurrent TCP connections to MSK broker port 9098 (IAM auth).
 *   2. Each connection initiates the SASL/OAUTHBEARER handshake.
 *   3. Each handshake triggers handleCallback() → resolveCredentials().
 *   4. 500 parallel IMDS or STS calls exceed rate limits.
 *   5. IMDS returns ThrottlingException; STS returns TooManyRequestsException.
 *   6. MSK broker's IAM auth fails for ALL clients, including legitimate ones.
 *   7. Producers and consumers cannot authenticate → full cluster outage.
 *
 * The attack requires no valid AWS credentials — only TCP connectivity to port 9098.
 *
 * FIX:
 *   Add a rate limiter (e.g., Guava RateLimiter) around resolveCredentials():
 *     private static final RateLimiter CREDENTIAL_LIMITER = RateLimiter.create(50.0);
 *     CREDENTIAL_LIMITER.acquire();
 *     AwsCredentials creds = credentialsProvider.resolveCredentials();
 *
 *   And add a credential cache with TTL to avoid re-resolving on every auth attempt.
 */
