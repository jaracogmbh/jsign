package net.jsign.util;

import net.jsign.model.CertificateDTO;
import net.jsign.model.SignatureResponse;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.logging.Logger;

public class CertificateService {
    private CertificateUtil certificateUtil = new CertificateUtil();
    private final Logger logger = Logger.getLogger(CertificateService.class.getName());

    public SignatureResponse getSignature(String endpoint) {
        logger.info("Getting signature from the server");
        try {
            // Create an instance of HttpClient
            HttpClient client = HttpClient.newHttpClient();

            URI uri = URI.create(endpoint + "/sign");
            String jsonBody =
                    "{" +
                      "\"hash\": \"base64 encoded hash\"," +
                      "\"signatureAlgorith\": \"SHA256WithRSA\"," +
                      "\"mgf1Algorithm\": \"SHA-256\"," +
                      "\"saltLenght\" : 0," +
                      "\"nonDecorateSignature\": false," +
                      "\"itsGroup\": \"groupname\"," +
                      "\"itsServiceId\": 12345," +
                      "\"user\": \"userID\"" +
                    "}";


            // Build the HttpRequest with the API endpoint URL
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "application/json")
                    .header("Authorization", "privateKey")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            logger.info("Sending request to the server: " + request);
            // Send the request and get the response
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Print the response
            SignatureResponse signature = certificateUtil.getSignature(response.body());
            return signature;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public CertificateDTO getCertificate(String alias, String endpoint) {
        logger.info("Getting certificate from the server");
        try {
            logger.info("Getting certificate with alias: " + alias);
            // Create an instance of HttpClient
            HttpClient client = HttpClient.newHttpClient();

            // Build the HttpRequest with the API endpoint URL
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI(endpoint + "/certificate?alias=" + alias))
                    .GET()  // for a GET request
                    .build();

            // Send the request and get the response
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            logger.info("Extracting certificate from the response");
            CertificateDTO certificate = certificateUtil.getCertificate(response.body());

            return certificate;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
