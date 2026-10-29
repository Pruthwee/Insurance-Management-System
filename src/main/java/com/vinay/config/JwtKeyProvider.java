package com.vinay.config;

import java.io.IOException;

import com.google.api.gax.rpc.ApiException;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretVersionName;

/**
 * Reads the JWT signing key from Google Secret Manager, lazily on first use.
 * The project comes from GCP_PROJECT_ID and the secret's name from JWT_KEY_SECRET.
 */
public final class JwtKeyProvider {

	private static final String PROJECT_ENV = "GCP_PROJECT_ID";
	private static final String SECRET_ENV = "JWT_KEY_SECRET";
	private static final String SECRET_VERSION = "latest";

	private static String cachedKey;

	private JwtKeyProvider() {
	}

	public static synchronized String getJwtKey() throws IOException {
		if (cachedKey != null) {
			return cachedKey;
		}
		String projectId = System.getenv(PROJECT_ENV);
		String secretId = System.getenv(SECRET_ENV);
		if (projectId == null || projectId.isEmpty()) {
			throw new IOException(PROJECT_ENV + " is not set");
		}
		if (secretId == null || secretId.isEmpty()) {
			throw new IOException(SECRET_ENV + " is not set");
		}
		try (SecretManagerServiceClient client = SecretManagerServiceClient.create()) {
			AccessSecretVersionResponse response = client
					.accessSecretVersion(SecretVersionName.of(projectId, secretId, SECRET_VERSION));
			cachedKey = response.getPayload().getData().toStringUtf8();
			return cachedKey;
		} catch (ApiException e) {
			throw new IOException("Unable to read the JWT signing key from Secret Manager", e);
		}
	}

}
