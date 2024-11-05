package net.jsign.jca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.jsign.DigestAlgorithm;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

/**
 * Custom signing service implementation for a mock API.
 */
public class CustomProviderService implements SigningService {

    private static final Logger logger = Logger.getLogger(CustomProviderService.class.getName());
    private final String endpoint;
    private final String apiKey;
    private final String alias = "default";
    private final Gson gson = new Gson();

    /**
     * Constructor for CustomProviderService.
     *
     * @param endpoint The API endpoint URL
     * @param apiKey   The x-api-key for authentication
     */
    public CustomProviderService(String endpoint, String apiKey) {
        if (endpoint == null) {
            endpoint = "http://localhost:8080";
        }
        logger.info("Initializing CustomProviderService with endpoint: " + endpoint);
        this.endpoint = endpoint;
        this.apiKey = apiKey;
    }

    @Override
    public String getName() {
        return "CustomProviderService";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        logger.info("Retrieving aliases for KeyStore");
        return Collections.singletonList(alias);
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        try {
            logger.info("Requesting certificate chain for alias: " + alias);
            Map<String, Object> response = httpGet("/getCertificateChain");
            logger.info("Received certificate chain response: " + response);

            List<String> encodedChain = (List<String>) response.get("certChain");
            List<Certificate> chain = new ArrayList<>();
            for (String encodedCert : encodedChain) {
                Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(Base64.getDecoder().decode(encodedCert)));
                chain.add(cert);
                logger.info("Decoded certificate added to chain: " + cert);
            }
            return chain.toArray(new Certificate[0]);

        } catch (IOException | CertificateException e) {
            logger.log(Level.SEVERE, "Failed to retrieve certificate chain", e);
            throw new KeyStoreException("Unable to retrieve certificate chain for alias: " + alias, e);
        }
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        logger.info("Retrieving private key for alias: " + alias);
        return new SigningServicePrivateKey("server-key-id", "RSA", this);
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        try {
            logger.info("Signing data with algorithm: " + algorithm);

            String digestAlgName = algorithm.substring(0, algorithm.indexOf("with"));
            DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(digestAlgName);
            byte[] hash = digestAlgorithm.getMessageDigest().digest(data);
            String hashBase64 = Base64.getEncoder().encodeToString(hash);
            logger.info("Computed hash (base64-encoded): " + hashBase64);

            Map<String, Object> requestPayload = Map.of("fileSha", hashBase64);
            logger.info("Sending sign request with payload: " + requestPayload);

            Map<String, Object> response = httpPost("/sign", requestPayload);
            logger.info("Received sign response: " + response);

            String signatureBase64 = (String) response.get("signature");
            return Base64.getDecoder().decode(signatureBase64);

        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to sign data with CustomProviderService", e);
            throw new GeneralSecurityException("Failed to sign data with CustomProviderService", e);
        }
    }

    // Helper methods for HTTP GET and POST requests

    private Map<String, Object> httpGet(String path) throws IOException {
        URL url = new URL(endpoint + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("x-api-key", apiKey);
        conn.setRequestProperty("Accept", "application/json");

        int responseCode = conn.getResponseCode();
        logger.info("GET Response Code :: " + responseCode);

        if (responseCode == HttpURLConnection.HTTP_OK) {
            InputStreamReader reader = new InputStreamReader(conn.getInputStream());
            Map<String, Object> response = gson.fromJson(reader, new TypeToken<Map<String, Object>>() {}.getType());
            reader.close();
            return response;
        } else {
            throw new IOException("GET request failed with response code " + responseCode);
        }
    }

    private Map<String, Object> httpPost(String path, Map<String, Object> payload) throws IOException {
        URL url = new URL(endpoint + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("x-api-key", apiKey);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Content-Type", "application/json; utf-8");
        conn.setDoOutput(true);

        String jsonInputString = gson.toJson(payload);
        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = jsonInputString.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        int responseCode = conn.getResponseCode();
        logger.info("POST Response Code :: " + responseCode);

        if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_CREATED) {
            InputStreamReader reader = new InputStreamReader(conn.getInputStream());
            Map<String, Object> response = gson.fromJson(reader, new TypeToken<Map<String, Object>>() {}.getType());
            reader.close();
            return response;
        } else {
            throw new IOException("POST request failed with response code " + responseCode);
        }
    }
}