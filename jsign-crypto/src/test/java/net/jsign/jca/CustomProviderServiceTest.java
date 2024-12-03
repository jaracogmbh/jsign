package net.jsign.jca;

import net.jsign.exception.FailedCertificateExtractionException;
import net.jsign.exception.FailedSignatureExtractionException;
import net.jsign.exception.NoEndpointSpecifiedException;
import net.jsign.exception.SignRequestFailedException;
import net.jsign.model.CertificateDTO;
import net.jsign.model.Chain;
import net.jsign.model.SignatureResponse;
import net.jsign.util.CertificateService;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

public class CustomProviderServiceTest {




   @Test
    public void getCertificateChainTest() throws NoEndpointSpecifiedException, KeyStoreException, IOException, InterruptedException, FailedCertificateExtractionException {
       CertificateService certificateService = Mockito.mock(CertificateService.class);
       String endpoint = "http://localhost:8089";
       String signAlgorithm = "SHA256withRSA";
       String mgfAlgorithm = "MGF1";
       int saltLength = 32;
       boolean nonDecorateSignature = false;
       String group = "group";
       String serviceId = "12345";
       String user = "user";
       String auth = "password";

       CustomProviderSigningService underTest = new CustomProviderSigningService(
               certificateService,
               endpoint,
               signAlgorithm,
               mgfAlgorithm,
               saltLength,
               nonDecorateSignature,
               group,
               serviceId,
               user,
               auth
       );
       String cert = "MIIDUDCCAjigAwIBAgIJAKQICQFhO1zTMA0GCSqGSIb3DQEBCwUAMCUxIzAhBgNVBAMMGkpzaWduIENvZGUgU2lnbmluZyBDQSAyMDIyMB4XDTIyMTExNTE4MTUzM1oXDTQyMTExMDE4MTUzM1owOTE3MDUGA1UEAwwuSnNpZ24gQ29kZSBTaWduaW5nIFRlc3QgQ2VydGlmaWNhdGUgMjAyMiAoUlNBKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKaQUuWQrHnHyjkdhwWdqT+W0g9t6vTnQmU4y/Xpg5wsF1NRMh2ujLj7PQx++l7fZJx3vC1JJ1/RM6CVFBYuazLwfDjl4/Nj4nglit+ijOJtXnBxSGIpKZTaORw9aYcMIvHRixZFqpVIfA0I7gjEB/WkI6Hq+ePu0ZGANorggJx/QP5IhBPzKSmv+83cQA954JN8EjdyuMzVs2SqOygUbKNai4jlmitEUyKB/29k9po+99pJ3KUQe+BHli3fyEFNzUdP9nB6FUw+9ko48/C0q7qKerKknYW3ysZwD70WMd40a/4U1cABSFbVvyIVAa4dxRoco52Gkt+x1GhOCztLtQ8CAwEAAaNvMG0wCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFBLEig5vFkfxsh/Oey8w5icoMTSTMB8GA1UdIwQYMBaAFJ9pNp0nqBx5bIhLCZF6EHl/ZnfaMA0GCSqGSIb3DQEBCwUAA4IBAQCFfbg7sXiWli9DyVz9LfrTzZOIwqilOSroemZ+W2YuKJEUs+NBBnmmmb2MQXZcm00fDKa0bSWJqGMfPeqsHZdMdlw4cZIhQ2wl67sdn/qtO8TpLcIZj2UlIgou8/afE6fN8w0mQPU9DOOPwDMzYQVJI3opuwVsAXj+82opBkx08yno2TIX7nt6PF51SMrqNVglzh8N31BAQ3CkjgPvnjDdgOxKsOubqFYzsMEtkmlF0EFS3BMJMvAHFGe1VRkhv1ejiBbaJXf50UGtJzgfnKYHR9HEaHoy4ka7FTHWKkEzjhsyjByGyVG8/jaelSJzqo3UbPXReg3yMPwWPqRpiCwh";
       Chain chain1 = new Chain("type", "MIIETTCCAjWgAwIBAgIJAMkyYFBPzGLZMA0GCSqGSIb3DQEBCwUAMDAxLjAsBgNVBAMMJUpzaWduIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMjIwHhcNMjIxMTE1MTgxNTMzWhcNNDIxMTEwMTgxNTMzWjAlMSMwIQYDVQQDDBpKc2lnbiBDb2RlIFNpZ25pbmcgQ0EgMjAyMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALpixZGfxZalF9pemY88A0E9HpOnxZNOPHeG054vm0SQNvr865ygHkXYcWZA/yRZ2SFQ/Y98Ne2buO5gXz7a7OOrF1qzsIGIo7b1p6ueFYthb1EDKArA6tEieiDzHI1PbNGbsGBwDZfVMDeIL003mMugFk0tIADmBEhDbxgRa+tMJ1CiN6ZZwUhSdX46WGPah0L+q+Iw0b6nbMl/r30R20utKIp8SPCg5JutOqBMGXuNg9CELIHTskdZkcA1BcKtW1Vbc9vloWlfvfWq8Xba2pqJ7pyV/UiJIjOBzdGZT2+cjsjcfJT20i8t/0o/sONS06WwKbz90OGWMc8W9z0dqBkCAwEAAaN1MHMwDwYDVR0TBAgwBgEB/wIBADALBgNVHQ8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFJ9pNp0nqBx5bIhLCZF6EHl/ZnfaMB8GA1UdIwQYMBaAFNsIlZmOYVuVCwdDzsLTMOIDKQM+MA0GCSqGSIb3DQEBCwUAA4ICAQAThD8CGA+/T/fdw4jFWs4yFCnkpDFOYnCAs0zvzY3GnN9dQ1RjwJ2UtCHg8KIid9tR89vMnYgyk4Jst948FaWr17qzVRL5AwuKeE8xW2a5i18Lw2SwszAafcywSZEeuGtE58zl23gymfH1ADWwh8C+VVDLMCX1pFQXNdC+3MAMs75/QYe625YaDodw6MjkTDHIr9yY+UTbjePEJhMXOE00pwKHe/5khKrgaEGCINcIFcU2CtbwGKm7cbI1cjoecGGO+bMdrzFc86kTgG1bTULYUxm/E0Dj3UBLs0s3WjX3pcxpucyQ3Q5tlWA45vXMqOfP4QJ8m0QOimp8Br8eOyAgx37EtXhqN1hZ16pjMYYzgnigZK2M6/+IJbHCf1x+opub9fsXbZ8jdBwDLSBqzgHFhSS6NjFSO6CBJoDJ9wdXLkCZL6MB27jFij8o5QtJul5LuBCeFbk8moGwN3E5/U6fb/lewb8+pPTlvsQnnSVFe13XFF9MWWw6G3m48cpWbD4Gut7BbjemrWqcs/954GmYNfHUkAbg5sSVw/eT/bYCwXvFj/Z8cXG9p0vRWWbeXBAounp5lHEVSRBxOxM/oiJsXTRXLTdDrY6gixRB+qVczrS5US0GSU9hOPWj4YJ5NDPaNfIdphEWOK2yUABAaYZV+sAI0/9AU5FYoofSuf2AuA==");
       CertificateDTO certificate = new CertificateDTO("1", cert, List.of(chain1));
       when(certificateService.getCertificate("dummy", endpoint, auth)).thenReturn(certificate);
       Certificate[] certificates = underTest.getCertificateChain("dummy");
       assertEquals(2, certificates.length);
   }


   @Test
   public void getCertificateChainFailedTest() throws NoEndpointSpecifiedException, FailedCertificateExtractionException, KeyStoreException {
       CertificateService certificateService = Mockito.mock(CertificateService.class);
       String endpoint = "http://localhost:8089";
       String signAlgorithm = "SHA256withRSA";
       String mgfAlgorithm = "MGF1";
       int saltLength = 32;
       boolean nonDecorateSignature = false;
       String group = "group";
       String serviceId = "12345";
       String user = "user";
       String auth = "password";

       CustomProviderSigningService underTest = new CustomProviderSigningService(
               certificateService,
               endpoint,
               signAlgorithm,
               mgfAlgorithm,
               saltLength,
               nonDecorateSignature,
               group,
               serviceId,
               user,
               auth
       );
       when(certificateService.getCertificate("dummy", endpoint, auth)).thenThrow(new FailedCertificateExtractionException("error"));
       Exception exception = assertThrows(KeyStoreException.class, () -> underTest.getCertificateChain("dummy"));
       assertEquals("Failed to get certificate from server for user with id: user", exception.getMessage());
       assertEquals("error", exception.getCause().getMessage());
       assertEquals(FailedCertificateExtractionException.class, exception.getCause().getClass());
   }

   @Test
   public void NoEndpointTest(){
       CertificateService certificateService = Mockito.mock(CertificateService.class);
         String endpoint = null;
         String signAlgorithm = "SHA256withRSA";
         String mgfAlgorithm = "MGF1";
         int saltLength = 32;
         boolean nonDecorateSignature = false;
         String group = "group";
         String serviceId = "12345";
         String user = "user";
         String auth = "password";
         try {
              CustomProviderSigningService underTest = new CustomProviderSigningService(
                     certificateService,
                     endpoint,
                     signAlgorithm,
                     mgfAlgorithm,
                     saltLength,
                     nonDecorateSignature,
                     group,
                     serviceId,
                     user,
                     auth
              );
         } catch (NoEndpointSpecifiedException e) {
              assertEquals("No endpoint specified for the signing service service", e.getMessage());
         }
   }

   @Test
   public void signSuccessTest() throws NoEndpointSpecifiedException, FailedCertificateExtractionException, GeneralSecurityException, FailedSignatureExtractionException, SignRequestFailedException {
       CertificateService certificateService = Mockito.mock(CertificateService.class);
       String endpoint = "http://localhost:8089";
       String signAlgorithm = "SHA256withRSA";
       String mgfAlgorithm = "MGF1";
       int saltLength = 32;
       boolean nonDecorateSignature = false;
       String group = "group";
       String serviceId = "12345";
       String user = "user";
       String auth = "password";
       byte[] data = "Das ist die Datei".getBytes();
       SigningServicePrivateKey key = new SigningServicePrivateKey("1", "RSA", null);
       byte[] expected = "this is the signature".getBytes();

       CustomProviderSigningService underTest = new CustomProviderSigningService(
               certificateService,
               endpoint,
               signAlgorithm,
               mgfAlgorithm,
               saltLength,
               nonDecorateSignature,
               group,
               serviceId,
               user,
               auth
       );

       String endcoded = Base64.getEncoder().encodeToString(expected);

       SignatureResponse response = new SignatureResponse(
                12354567L,
               endcoded,
               "2030-11-23T18:25:43.511Z",
                "353d4f18-4b78-b17c-5325-f92375cf40ec",
                "a68e1ae4-41ac-b140-ad1e-3219ff08a4e9",
                "SUCCESS",
               null
       );
       doReturn(response).when(certificateService).getSignature(anyString(), any(byte[].class), anyString(), anyString(), anyInt(), anyBoolean(), anyString(), anyString(), anyString(), anyString());
       byte[] result = underTest.sign(key, "RSA", data);
       assertEquals(new String(expected), new String(result));
   }

    @Test
    public void signFailedTest() throws NoEndpointSpecifiedException, FailedCertificateExtractionException, GeneralSecurityException, FailedSignatureExtractionException {
        CertificateService certificateService = Mockito.mock(CertificateService.class);
        String endpoint = "http://localhost:8089";
        String signAlgorithm = "SHA256withRSA";
        String mgfAlgorithm = "MGF1";
        int saltLength = 32;
        boolean nonDecorateSignature = false;
        String group = "group";
        String serviceId = "12345";
        String user = "user";
        String auth = "password";
        byte[] data = "Das ist die Datei".getBytes();
        SigningServicePrivateKey key = new SigningServicePrivateKey("1", "RSA", null);
        byte[] expected = "this is the signature".getBytes();

        CustomProviderSigningService underTest = new CustomProviderSigningService(
                certificateService,
                endpoint,
                signAlgorithm,
                mgfAlgorithm,
                saltLength,
                nonDecorateSignature,
                group,
                serviceId,
                user,
                auth
        );
        String endcoded = Base64.getEncoder().encodeToString(expected);

        SignatureResponse response = new SignatureResponse(
                12354567L,
                endcoded,
                "2030-11-23T18:25:43.511Z",
                "353d4f18-4b78-b17c-5325-f92375cf40ec",
                "a68e1ae4-41ac-b140-ad1e-3219ff08a4e9",
                "FAILED",
                "error"
        );

        when(certificateService.getSignature(anyString(), any(byte[].class), anyString(), anyString(), anyInt(), anyBoolean(), anyString(), anyString(), anyString(), anyString())).thenReturn(response);
        Exception exception = assertThrows(GeneralSecurityException.class, () -> underTest.sign(key, "RSA", data));
        assertEquals(SignRequestFailedException.class, exception.getCause().getClass());
        assertEquals("error", exception.getCause().getMessage());
        assertEquals("Failed to sign data with certificate", exception.getMessage());
    }

}
