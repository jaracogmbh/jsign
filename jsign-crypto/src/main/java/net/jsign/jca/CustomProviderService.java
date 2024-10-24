package net.jsign.jca;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import net.jsign.DigestAlgorithm;

/**
 * Custom signing service impl
 */
public class CustomProviderService implements SigningService {

    private final RESTClient client;
    private final String alias = "default";

    /**
     * Constructor for CustomProviderService
     *
     * @param endpoint The API endpoint URL
     * @param apiKey   The x-api-key for authentication
     */
    public CustomProviderService(String endpoint, String apiKey) {
        if (endpoint == null) {
            endpoint = "http://localhost:8080";
        }
        this.client = new RESTClient(endpoint)
                .authentication(conn -> {
                    conn.setRequestProperty("x-api-key", apiKey);
                })
                .errorHandler(response -> {
                    Map<?, ?> error = (Map<?, ?>) response.get("error");
                    return error != null ? error.get("status") + ": " + error.get("message") : response.toString();
                });
    }

    @Override
    public String getName() {
        return "CustomProviderService";
    }

    @Override
    public List<String> aliases() throws KeyStoreException { // we do not have multiple keys
        return Collections.singletonList(alias);
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        // if API provides the certificate chain, it's correct place to implement it
        // for now, return null
        return null;
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        // dummy private key reference since "signing" is done on the server
        return new SigningServicePrivateKey("server-key-id", "RSA", this);
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        try {
            // compute the hash of the data using the specified algorithm
            String digestAlgName = algorithm.substring(0, algorithm.indexOf("with"));
            DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(digestAlgName);
            byte[] hash = digestAlgorithm.getMessageDigest().digest(data);

            // perepare the request payload
            Map<String, Object> request = Map.of(
                    "fileSha", Base64.getEncoder().encodeToString(hash)
            );

            // send the signing request to the backend
            Map<String, ?> response = client.post("/sign", JsonWriter.format(request));

            // signature from the response
            String signatureBase64 = (String) response.get("signature");
            return Base64.getDecoder().decode(signatureBase64);

        } catch (IOException e) {
            throw new GeneralSecurityException("Failed to sign data with CustomProviderService", e);
        }
    }
}