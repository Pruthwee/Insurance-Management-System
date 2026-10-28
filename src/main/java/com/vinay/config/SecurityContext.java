package com.vinay.config;

/**
 * SecurityContext holds non-sensitive, structural JWT constants.
 *
 * The JWT signing key (previously hard-coded here) has been removed and is now
 * retrieved at runtime from Google Secret Manager via {@link GcpSecretManagerService}.
 *
 * Secret name expected in GCP Secret Manager: "jwt-secret-key"
 * (configure the GCP project via the environment variable GCP_PROJECT_ID or
 *  the Spring property gcp.project-id)
 */
public interface SecurityContext {

    /**
     * HTTP header name used to carry the JWT token.
     * This is a structural constant and does NOT contain sensitive data.
     */
    String JWT_HEADER = "Authorization";

    /**
     * Name of the secret stored in Google Secret Manager that holds the JWT signing key.
     * The actual secret value is fetched at runtime by {@link GcpSecretManagerService}.
     */
    String JWT_SECRET_NAME = "jwt-secret-key";
}
