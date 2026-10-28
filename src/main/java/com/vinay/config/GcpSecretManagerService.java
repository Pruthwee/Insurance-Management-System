package com.vinay.config;

import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

/**
 * Service that retrieves secrets from Google Cloud Secret Manager.
 *
 * The GCP project is resolved from the Spring property {@code gcp.project-id},
 * which should be set via the environment variable {@code GCP_PROJECT_ID}.
 *
 * Usage example (application.properties / environment):
 *   gcp.project-id=${GCP_PROJECT_ID}
 *
 * The JWT signing key is stored in Secret Manager under the name defined by
 * {@link SecurityContext#JWT_SECRET_NAME} ("jwt-secret-key").
 */
@Service
public class GcpSecretManagerService {

    private static final Logger logger = LoggerFactory.getLogger(GcpSecretManagerService.class);

    @Value("${gcp.project-id}")
    private String gcpProjectId;

    private String jwtSecretKey;

    /**
     * Eagerly loads the JWT secret from GCP Secret Manager on application startup.
     * This avoids repeated remote calls during request processing.
     */
    @PostConstruct
    public void loadSecrets() {
        this.jwtSecretKey = fetchSecret(SecurityContext.JWT_SECRET_NAME);
        logger.info("JWT secret key successfully loaded from GCP Secret Manager "
                + "(secret name: {})", SecurityContext.JWT_SECRET_NAME);
    }

    /**
     * Returns the JWT signing key retrieved from GCP Secret Manager.
     *
     * @return the JWT signing key as a plain string
     */
    public String getJwtSecretKey() {
        return jwtSecretKey;
    }

    /**
     * Fetches the latest version of a named secret from GCP Secret Manager.
     *
     * @param secretName the name of the secret (without project/version path)
     * @return the secret payload as a UTF-8 string
     * @throws RuntimeException if the secret cannot be retrieved
     */
    private String fetchSecret(String secretName) {
        try (SecretManagerServiceClient client = SecretManagerServiceClient.create()) {
            SecretVersionName secretVersionName =
                    SecretVersionName.of(gcpProjectId, secretName, "latest");
            AccessSecretVersionResponse response = client.accessSecretVersion(secretVersionName);
            return response.getPayload().getData().toStringUtf8();
        } catch (Exception e) {
            logger.error("Failed to retrieve secret '{}' from GCP Secret Manager: {}",
                    secretName, e.getMessage());
            throw new RuntimeException(
                    "Unable to load secret '" + secretName + "' from GCP Secret Manager", e);
        }
    }
}
