package com.vinay.config;

import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.core.exception.AzureException;

public class SecretManager {

	private SecretClient secretClient;

	private synchronized SecretClient getSecretClient() {
		if (secretClient == null) {
			String keyVaultUrl = System.getenv("KEY_VAULT_URL");
			if (keyVaultUrl == null || keyVaultUrl.isEmpty()) {
				throw new IllegalStateException("KEY_VAULT_URL is not set");
			}
			DefaultAzureCredential credential = new DefaultAzureCredentialBuilder()
					.build();
			this.secretClient = new SecretClientBuilder()
					.vaultUrl(keyVaultUrl)
					.credential(credential)
					.buildClient();
		}
		return secretClient;
	}

	public String getSecret(String secretName) {
		try {
			return getSecretClient().getSecret(secretName).getValue();
		} catch (AzureException | IllegalStateException e) {
			throw new RuntimeException("Failed to retrieve secret: " + secretName, e);
		}
	}
}
