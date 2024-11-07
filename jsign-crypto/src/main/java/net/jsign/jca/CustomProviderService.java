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

import net.jsign.exception.FailedCertificateExtractionException;
import net.jsign.exception.FailedSignatureExtractionException;
import net.jsign.exception.NoEndpointSpecifiedException;
import net.jsign.exception.SignRequestFailedException;
import net.jsign.model.CertificateDTO;
import net.jsign.model.Chain;
import net.jsign.model.SignatureResponse;
import net.jsign.util.CertificateService;

/**
 * Custom signing service implementation for a mock API.
 */
public class CustomProviderService implements SigningService {

    private CertificateService certificateService = new CertificateService();
    private final Logger logger = Logger.getLogger(DigiCertOneSigningService.class.getName());

    private final String alias = "default";
    private final List<Certificate> certificates = new ArrayList<>();
    private String endpoint;
    String signAlgorithm;
    String mgfAlgorithm;
    int saltLength;
    boolean nonDecorateSignature;
    String group;
    int serviceId;
    String user;
    String auth;

    /**
     * Constructor for CustomProviderService.
     *
     * @param endpoint The API endpoint URL
     * @param apiKey   The x-api-key for authentication
     */
    public CustomProviderService(String endpoint,
                                 String signAlgorithm,
                                 String mgfAlgorithm,
                                 int saltLength,
                                 boolean nonDecorateSignature,
                                 String group,
                                 int serviceId,
                                 String user,
                                 String auth) throws NoEndpointSpecifiedException {
        if (endpoint == null) {
            throw new NoEndpointSpecifiedException("No endpoint specified for the signing service service");
        }else{
            logger.info("Initializing CustomProviderService with endpoint: " + endpoint);
            logger.info("Setting endpoint to: " + endpoint);
            this.endpoint = endpoint;
        }
        logger.info("Setting sign algorithm to: " + signAlgorithm);
        this.signAlgorithm = signAlgorithm;
        logger.info("Setting mask generation function to: " + mgfAlgorithm);
        this.mgfAlgorithm = mgfAlgorithm;
        logger.info("Setting salt length to: " + saltLength);
        this.saltLength = saltLength;
        logger.info("Setting non decorate signature to: " + nonDecorateSignature);
        this.nonDecorateSignature = nonDecorateSignature;
        logger.info("Setting group to: " + group);
        this.group = group;
        logger.info("Setting service id to: " + serviceId);
        this.serviceId = serviceId;
        logger.info("Setting user to: " + user);
        this.user = user;
        logger.info("Setting auth to: " + auth);
        this.auth = auth;
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
        logger.info("Getting certificate chain from server");
        try{
            CertificateDTO certificate = certificateService.getCertificate(alias, endpoint, auth);
            List<String> encodedChain = new ArrayList<>();
            encodedChain.add((String) certificate.getCert());
            List<Chain> chainList = certificate.getChain();
            for(Chain c : chainList){
                encodedChain.add(c.getBlob());
            }
            List<Certificate> chain = new ArrayList<>();
            for (String encodedCertificate : encodedChain) {
                Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate)));
                chain.add(cert);
                certificates.add(cert);
            }
            return chain.toArray(new Certificate[0]);
        } catch (CertificateException | FailedCertificateExtractionException e) {
            logger.severe("Failed to get certificate chain from server for user with id: " + user);
            throw new KeyStoreException("Failed to get certificate from server for user with id: " + user, e);
        }
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        try{
            logger.info("Skipping this method");
            return new SigningServicePrivateKey("server-key-id", "RSA", this);
        } catch (Exception e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch DigiCert ONE private key for the certificate '" + alias + "'").initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException, FailedSignatureExtractionException, SignRequestFailedException {
        logger.info("Signing data with certificate");
        SignatureResponse signature = certificateService.getSignature(endpoint, data, signAlgorithm, mgfAlgorithm, saltLength, nonDecorateSignature, group, serviceId, user, auth);
        if(signature.getSignReturnCode() == "FAILED"){
            logger.info("Failed to sign data with certificate!");
            String errorMessage = signature.getErrorMessage();
            logger.info("An error occured while creating the signature on the server site: " + signature.getErrorMessage());
            throw new SignRequestFailedException(errorMessage);
        }else{
            logger.info("Successfully signed data with certificate");
            return Base64.getDecoder().decode(signature.getSignedHash());
        }
    }

    // Helper methods for HTTP GET and POST requests

    /*private Map<String, Object> httpGet(String path) throws IOException {
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
    }*/
}