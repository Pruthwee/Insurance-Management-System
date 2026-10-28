package com.vinay.config;

import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

/**
 * Reads the JWT signing key from AWS Secrets Manager. The name of the secret
 * comes from the JWT_SECRET_NAME environment variable; region and credentials
 * come from the AWS SDK default chain. The client is built lazily on first use
 * and the key is cached for a short time.
 */
public final class JwtSecretProvider {

	private static final String SECRET_NAME_ENV = "JWT_SECRET_NAME";
	private static final long CACHE_TTL_MS = 300_000L;

	private static SecretsManagerClient client;
	private static String cachedKey;
	private static long lastFetchTime;

	private JwtSecretProvider() {
	}

	/**
	 * @return the JWT signing key
	 * @throws IllegalStateException if the secret name is not configured
	 * @throws software.amazon.awssdk.core.exception.SdkException if the secret cannot be read
	 */
	public static synchronized String getJwtKey() {
		long now = System.currentTimeMillis();
		if (cachedKey != null && (now - lastFetchTime) <= CACHE_TTL_MS) {
			return cachedKey;
		}
		String secretName = System.getenv(SECRET_NAME_ENV);
		if (secretName == null || secretName.isBlank()) {
			throw new IllegalStateException(SECRET_NAME_ENV + " is not set");
		}
		if (client == null) {
			client = SecretsManagerClient.create();
		}
		String value = client.getSecretValue(GetSecretValueRequest.builder().secretId(secretName).build())
				.secretString();
		if (value == null || value.isEmpty()) {
			throw new IllegalStateException("The JWT secret has no string value");
		}
		cachedKey = value;
		lastFetchTime = now;
		return cachedKey;
	}
}
