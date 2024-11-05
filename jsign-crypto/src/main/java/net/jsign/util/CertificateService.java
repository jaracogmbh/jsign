package net.jsign.util;

import net.jsign.model.CertificateDTO;
import net.jsign.model.CertificateList;
import net.jsign.model.Signature;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class CertificateService {
    private CertificateUtil certificateUtil = new CertificateUtil();

    public Signature getSignature() {
        try {
            // Create an instance of HttpClient
            HttpClient client = HttpClient.newHttpClient();

            // Build the HttpRequest with the API endpoint URL
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI("http://localhost:8089/sign"))
                    .GET()  // for a GET request
                    .build();

            // Send the request and get the response
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Print the response
            System.out.println("Status code: " + response.statusCode());
            System.out.println("Response body: " + response.body());
            Signature signature = certificateUtil.getSignature(response.body());
            return signature;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public CertificateDTO getCertificate(String alias) {
        try {
            // Create an instance of HttpClient
            HttpClient client = HttpClient.newHttpClient();

            // Build the HttpRequest with the API endpoint URL
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI("http://localhost:8089/certificate?alias=" + alias))
                    .GET()  // for a GET request
                    .build();

            // Send the request and get the response
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Print the response
            System.out.println("Status code: " + response.statusCode());
            System.out.println("Response body: " + response.body());
            CertificateDTO certificate = certificateUtil.getCertificate(response.body());

            return certificate;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
