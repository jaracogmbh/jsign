package net.jsign.util;

import net.jsign.exception.FailedCertificateExtractionException;
import net.jsign.exception.FailedSignatureExtractionException;
import net.jsign.model.CertificateDTO;
import net.jsign.model.SignatureResponse;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.logging.Logger;

public class CertificateService {
    private CertificateUtil certificateUtil = new CertificateUtil();
    private final Logger logger = Logger.getLogger(CertificateService.class.getName());

    public SignatureResponse getSignature(
            String endpoint,
            byte[] data,
            String signatureAlgorithm,
            String mgf1Algorithm,
            int saltLength,
            boolean nonDecorateSignature,
            String itsGroup,
            int itsServiceId,
            String user,
            String auth
            ) throws FailedSignatureExtractionException {
        logger.info("Getting signature from the server");
        try {
            String fileHash = this.convertToBase64(data);
            logger.info("Getting signature for hash value: " + fileHash);
            HttpClient client = HttpClient.newHttpClient();

            URI uri = URI.create(endpoint + "/sign");
            String jsonBody =
                    "{" +
                      "\"hash\": \"" + fileHash + "\"," +
                      "\"signatureAlgorith\": \"" + signatureAlgorithm +"\"," +
                      "\"mgf1Algorithm\": \"" + mgf1Algorithm +"\"," +
                      "\"saltLenght\" : " + saltLength + "," +
                      "\"nonDecorateSignature\": "+nonDecorateSignature+"," +
                      "\"itsGroup\": \""+itsGroup+"\"," +
                      "\"itsServiceId\": "+itsServiceId+"," +
                      "\"user\": \""+user+"\"" +
                    "}";


            logger.info("Building the request");
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "application/json")
                    .header("Authorization", auth)
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            logger.info("Sending request to the server: " + request);
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            SignatureResponse signature = certificateUtil.getSignature(response.body());
            return signature;
        } catch (Exception e) {
            logger.severe("Error getting signature from the server: " + e.getMessage());
            throw new FailedSignatureExtractionException(e.getMessage());
        }

    }

    public CertificateDTO getCertificate(String alias, String endpoint, String auth) throws FailedCertificateExtractionException {
        logger.info("Getting certificate from the server");
        int statusCode = 0;
        try {
           logger.info("Building the request");
            HttpClient client = HttpClient.newHttpClient();
            // Build the HttpRequest with the API endpoint URL
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI(endpoint + "/certificate"))
                    .header("Authorization", auth)
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            logger.info("Extracting certificate from the response");
            CertificateDTO certificate = certificateUtil.getCertificate(response.body());
            statusCode = response.statusCode();
            return certificate;
        } catch (Exception e) {
            logger.severe("Error getting certificate from the server: " + e.getMessage());
            throw new FailedCertificateExtractionException(e.getMessage());
        }
    }

    public String convertToBase64(byte[] data) {
        String encoded = Base64.getEncoder().encodeToString(data);
        logger.info("converted to base64: " + encoded);
        return encoded;
    }

}
