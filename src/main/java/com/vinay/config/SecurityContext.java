package com.vinay.config;

import java.io.IOException;

import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

public class SecurityContext {

	public static final String JWT_HEADER = "Authorization";

	private static final String JWT_SECRET_NAME_ENV = "JWT_SECRET_NAME";

	private static volatile SecretsManagerClient secretsClient;

	public static String getJwtKey() throws IOException {
		String secretName = System.getenv(JWT_SECRET_NAME_ENV);
		if (secretName == null || secretName.isEmpty()) {
			throw new IOException(JWT_SECRET_NAME_ENV + " is not set");
		}

		if (secretsClient == null) {
			synchronized (SecurityContext.class) {
				if (secretsClient == null) {
					secretsClient = SecretsManagerClient.builder().build();
				}
			}
		}

		try {
			GetSecretValueRequest request = GetSecretValueRequest.builder()
					.secretId(secretName)
					.build();

			GetSecretValueResponse response = secretsClient.getSecretValue(request);
			return response.secretString();
		} catch (SdkException e) {
			throw new IOException("Failed to retrieve JWT secret from Secrets Manager", e);
		}
	}
}
