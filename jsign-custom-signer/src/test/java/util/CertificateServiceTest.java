package util;

import net.jsign.exception.FailedCertificateExtractionException;
import net.jsign.exception.FailedSignatureExtractionException;
import net.jsign.model.CertificateDTO;
import net.jsign.model.SignatureResponse;
import net.jsign.util.CertificateService;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class CertificateServiceTest {

    HttpClient httpClient = Mockito.mock(HttpClient.class);
    CertificateService underTest = new CertificateService(httpClient);;

    @Test
    public void testGetCertificateOK() throws IOException, InterruptedException, FailedCertificateExtractionException {
        String alias = "dummy";
        String endpoint = "http://localhost:8089";
        String auth = "password";
        HttpResponse<String> response = Mockito.mock(HttpResponse.class);
        when(httpClient.send(any(), eq(HttpResponse.BodyHandlers.ofString()))).thenReturn(response);
        when(response.body()).thenReturn("{" +
                "\"id\":\"1\"," +
                "\"cert\":\"cert\"," +
                "\"chain\":[" +
                "{" +
                "\"type\":\"type\",\"blob\":\"blob\"}]" +
                "}"
        );
        when(response.statusCode()).thenReturn(200);
        CertificateDTO result = underTest.getCertificate(alias, endpoint, auth);
        assertEquals("1", result.getId());
        assertEquals("cert", result.getCert());
        assertEquals(1, result.getChain().size());
        assertEquals("type", result.getChain().get(0).getType());
        assertEquals("blob", result.getChain().get(0).getBlob());
    }

    @Test
    public void testGetCertificateBadRequest() throws IOException, InterruptedException, FailedCertificateExtractionException {
        String alias = "dummy";
        String endpoint = "http://localhost:8089";
        String auth = "password";
        HttpResponse<String> response = Mockito.mock(HttpResponse.class);
        when(httpClient.send(any(), eq(HttpResponse.BodyHandlers.ofString()))).thenReturn(response);
        when(response.body()).thenReturn("error");
        when(response.statusCode()).thenReturn(500);
        try {
            underTest.getCertificate(alias, endpoint, auth);
        } catch (FailedCertificateExtractionException e) {
            assertEquals("error", e.getMessage());
        }
    }

    @Test
    public void getSigatureOK() throws IOException, InterruptedException, FailedCertificateExtractionException, FailedSignatureExtractionException {
        String endpoint = "http://localhost:8089";
        String auth = "password";
        byte[] data = "Das ist die Datei".getBytes();
        HttpResponse<String> response = Mockito.mock(HttpResponse.class);
        when(httpClient.send(any(), eq(HttpResponse.BodyHandlers.ofString()))).thenReturn(response);
        when(response.body()).thenReturn("{\n" +
                "  \"signTime\": 1235456,\n" +
                "  \"signedHash\": \"v686SHskn4n/\",\n" +
                "  \"validUntil\": \"2030-11-23T18:25:43.511Z\",\n" +
                "  \"certificateId\": \"353d4f18-4b78-b17c-5325-f92375cf40ec\",\n" +
                "  \"signCertificate\": \"a68e1ae4-41ac-b140-ad1e-3219ff08a4e9\",\n" +
                "  \"signReturnCode\" : \"SUCCESS\",\n" +
                "  \"errorMessage\" : null\n" +
                "}"
        );
        when(response.statusCode()).thenReturn(200);
        SignatureResponse result = underTest.getSignature(endpoint, data, "SHA256withRSA", "MGF1", 32, true, "group", "1234", "user", auth);
        assertEquals(1235456, result.getSignTime().longValue());
        assertEquals("v686SHskn4n/", result.getSignedHash());
        assertEquals("2030-11-23T18:25:43.511Z", result.getValidUntil());
        assertEquals("353d4f18-4b78-b17c-5325-f92375cf40ec", result.getCertificateId());
        assertEquals("a68e1ae4-41ac-b140-ad1e-3219ff08a4e9", result.getSignCertificate());
        assertEquals("SUCCESS", result.getSignReturnCode());
        assertEquals(null, result.getErrorMessage());
    }

    @Test
    public void getSigatureBadRequest() throws IOException, InterruptedException, FailedCertificateExtractionException, FailedSignatureExtractionException {
        String endpoint = "http://localhost:8089";
        String auth = "password";
        byte[] data = "Das ist die Datei".getBytes();
        HttpResponse<String> response = Mockito.mock(HttpResponse.class);
        when(httpClient.send(any(), eq(HttpResponse.BodyHandlers.ofString()))).thenReturn(response);
        when(response.body()).thenReturn("error");
        when(response.statusCode()).thenReturn(500);
        try {
            underTest.getSignature(endpoint, data, "SHA256withRSA", "MGF1", 32, true, "group", "1234", "user", auth);
        } catch (FailedSignatureExtractionException e) {
            assertEquals("error", e.getMessage());
        }
    }

}
