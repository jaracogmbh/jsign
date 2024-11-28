package util;

import net.jsign.exception.JsonResponseIncorrectException;
import net.jsign.model.CertificateDTO;
import net.jsign.model.SignatureResponse;
import net.jsign.util.CertificateUtil;
import org.junit.Test;

import static org.junit.Assert.*;

public class CertificateUtilTest {
    CertificateUtil underTest = new CertificateUtil();


    @Test
    public void testGetCertificate() throws JsonResponseIncorrectException {
        // Given
        String jsonString = "{\n" +
                "  \"id\": \"353d4f18-4b78-b17c-5325-f92375cf40ec\",\n" +
                "  \"cert\": \"MIIDUDCCAjigAwIBAgIJAKQICQFhO1zTMA0GCSqGSIb3DQEBCwUAMCUxIzAhBgNVBAMMGkpzaWduIENvZGUgU2lnbmluZyBDQSAyMDIyMB4XDTIyMTExNTE4MTUzM1oXDTQyMTExMDE4MTUzM1owOTE3MDUGA1UEAwwuSnNpZ24gQ29kZSBTaWduaW5nIFRlc3QgQ2VydGlmaWNhdGUgMjAyMiAoUlNBKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKaQUuWQrHnHyjkdhwWdqT+W0g9t6vTnQmU4y/Xpg5wsF1NRMh2ujLj7PQx++l7fZJx3vC1JJ1/RM6CVFBYuazLwfDjl4/Nj4nglit+ijOJtXnBxSGIpKZTaORw9aYcMIvHRixZFqpVIfA0I7gjEB/WkI6Hq+ePu0ZGANorggJx/QP5IhBPzKSmv+83cQA954JN8EjdyuMzVs2SqOygUbKNai4jlmitEUyKB/29k9po+99pJ3KUQe+BHli3fyEFNzUdP9nB6FUw+9ko48/C0q7qKerKknYW3ysZwD70WMd40a/4U1cABSFbVvyIVAa4dxRoco52Gkt+x1GhOCztLtQ8CAwEAAaNvMG0wCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFBLEig5vFkfxsh/Oey8w5icoMTSTMB8GA1UdIwQYMBaAFJ9pNp0nqBx5bIhLCZF6EHl/ZnfaMA0GCSqGSIb3DQEBCwUAA4IBAQCFfbg7sXiWli9DyVz9LfrTzZOIwqilOSroemZ+W2YuKJEUs+NBBnmmmb2MQXZcm00fDKa0bSWJqGMfPeqsHZdMdlw4cZIhQ2wl67sdn/qtO8TpLcIZj2UlIgou8/afE6fN8w0mQPU9DOOPwDMzYQVJI3opuwVsAXj+82opBkx08yno2TIX7nt6PF51SMrqNVglzh8N31BAQ3CkjgPvnjDdgOxKsOubqFYzsMEtkmlF0EFS3BMJMvAHFGe1VRkhv1ejiBbaJXf50UGtJzgfnKYHR9HEaHoy4ka7FTHWKkEzjhsyjByGyVG8/jaelSJzqo3UbPXReg3yMPwWPqRpiCwh\",\n" +
                "  \"chain\": [\n" +
                "    {\n" +
                "      \"type\": \"intermediate\",\n" +
                "      \"blob\": \"MIIETTCCAjWgAwIBAgIJAMkyYFBPzGLZMA0GCSqGSIb3DQEBCwUAMDAxLjAsBgNVBAMMJUpzaWduIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMjIwHhcNMjIxMTE1MTgxNTMzWhcNNDIxMTEwMTgxNTMzWjAlMSMwIQYDVQQDDBpKc2lnbiBDb2RlIFNpZ25pbmcgQ0EgMjAyMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALpixZGfxZalF9pemY88A0E9HpOnxZNOPHeG054vm0SQNvr865ygHkXYcWZA/yRZ2SFQ/Y98Ne2buO5gXz7a7OOrF1qzsIGIo7b1p6ueFYthb1EDKArA6tEieiDzHI1PbNGbsGBwDZfVMDeIL003mMugFk0tIADmBEhDbxgRa+tMJ1CiN6ZZwUhSdX46WGPah0L+q+Iw0b6nbMl/r30R20utKIp8SPCg5JutOqBMGXuNg9CELIHTskdZkcA1BcKtW1Vbc9vloWlfvfWq8Xba2pqJ7pyV/UiJIjOBzdGZT2+cjsjcfJT20i8t/0o/sONS06WwKbz90OGWMc8W9z0dqBkCAwEAAaN1MHMwDwYDVR0TBAgwBgEB/wIBADALBgNVHQ8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFJ9pNp0nqBx5bIhLCZF6EHl/ZnfaMB8GA1UdIwQYMBaAFNsIlZmOYVuVCwdDzsLTMOIDKQM+MA0GCSqGSIb3DQEBCwUAA4ICAQAThD8CGA+/T/fdw4jFWs4yFCnkpDFOYnCAs0zvzY3GnN9dQ1RjwJ2UtCHg8KIid9tR89vMnYgyk4Jst948FaWr17qzVRL5AwuKeE8xW2a5i18Lw2SwszAafcywSZEeuGtE58zl23gymfH1ADWwh8C+VVDLMCX1pFQXNdC+3MAMs75/QYe625YaDodw6MjkTDHIr9yY+UTbjePEJhMXOE00pwKHe/5khKrgaEGCINcIFcU2CtbwGKm7cbI1cjoecGGO+bMdrzFc86kTgG1bTULYUxm/E0Dj3UBLs0s3WjX3pcxpucyQ3Q5tlWA45vXMqOfP4QJ8m0QOimp8Br8eOyAgx37EtXhqN1hZ16pjMYYzgnigZK2M6/+IJbHCf1x+opub9fsXbZ8jdBwDLSBqzgHFhSS6NjFSO6CBJoDJ9wdXLkCZL6MB27jFij8o5QtJul5LuBCeFbk8moGwN3E5/U6fb/lewb8+pPTlvsQnnSVFe13XFF9MWWw6G3m48cpWbD4Gut7BbjemrWqcs/954GmYNfHUkAbg5sSVw/eT/bYCwXvFj/Z8cXG9p0vRWWbeXBAounp5lHEVSRBxOxM/oiJsXTRXLTdDrY6gixRB+qVczrS5US0GSU9hOPWj4YJ5NDPaNfIdphEWOK2yUABAaYZV+sAI0/9AU5FYoofSuf2AuA==\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"type\": \"root\",\n" +
                "      \"blob\": \"MIIFNjCCAx6gAwIBAgIJAJCKzj9nrGsjMA0GCSqGSIb3DQEBCwUAMDAxLjAsBgNVBAMMJUpzaWduIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMjIwHhcNMjIxMTE1MTgxNTMzWhcNNDIxMTEwMTgxNTMzWjAwMS4wLAYDVQQDDCVKc2lnbiBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDIyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqZRI3F6Sy1CvX0TzXQ+UgiEHdolh9e+L7+TuqrSiHC3L35EQxo7DUc7mHLwXT8p2WUZcy1k47rYUytaZ7clXREMjGAyDJ1mGp0MLeHWUp5IMZEl00j8dRrftawfGADj2IOmm9jZsPQnzJ4rl/MsB51h/z12Qh7Mtn1VHGM7+yVdUr0XVDaJkxL+jPhhAWR3rzZSOI5w5abgV2c0xqJJbsT/L342vBQq6Kg1QvGJiWfALj/spA39G94P92xoLAbV68BDWBnsIE6jRIf+ju7SEX7xBVFBN6nVx6bav/G5aktAnoF5B0bREkC2tKHFVntciyAaCPlff0Q6SM749gKvFi+m+tmupFQ55U9JjEEzlifSSunlNvqCxkR8dBCfTgi9WZ/8b6nR96GKH28xy+zn7xZSyuBpICmFY2aYQfs9gguz0EDhXxoy7mD2sf+fne40Np0kWiFHV46PZ32oRmWExVFDjXl6AVYpTc+FFDgLcm9wqq3jiCS1Qx+MbfoLqJ5DSabdpkjMsqgbWSdTCF8oMzaAn30EsZwgTPw8z2Oyhz4kAxeXeE50hn+SnEsdZ7HlPn2ANhq36qI61VVY4Yw0MQBHMXw6mOVC8TESY2A/iWf3iHh2CEkltTdyASYW70eJ3T0zBcmoDT28i+xD46HL9rWJ7O1Lc0HEwDx8w2ktrM4ECAwEAAaNTMFEwHQYDVR0OBBYEFNsIlZmOYVuVCwdDzsLTMOIDKQM+MB8GA1UdIwQYMBaAFNsIlZmOYVuVCwdDzsLTMOIDKQM+MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBADfPJGlZAGSVQRGOaVhOyokP/wCSQ/DKxAXUx/KQ7vGH19ATIyaWeKl3x3Py/Cd7+2v2yxq7PQqsk6n+M6N7TzRSfIIqxhBkJsAooCUAJFDNQU4bMvnbhcIAn/w0i5ba7A5SQ2r5Dp2+n4ilVMf1mYnkeEMO+asJhkhqNVMQL3G70C1+yIDQaBV9L4lZAS+50wS+x/ZS5HK/aOG5RZWwn7UP71xawDV7v3Vr+H95mPj8De78SAqkCcXlJtvXjDdoBE8rynMDS0EatXnRjxZgb7rOfOeJGXn/AF1PM4rQy7fJrcWtZHsG5ScXJaJu1jWKPGXEJa3BTw4BJRK/8fffN5XW7RfFLNYVvD+JGEJF4pkS2WXkgafFN7wkYbj9AyjHT4AhJykZeIWBMllV7kAg73uQSkNw18VjpqIWXzVLIcdgi1O+8EAglYUEwUIAl2Cn3f9MACwg12J+8OUEc57OLfqeIZ/JPbIIvSw25RY/D9KqP/OtEXOF+9FSqYZ9xadHyUaGf/OopUMz2MTQ8hrmBBMRrq4SE/xk4UNtPgMGqMeBKKnGXQXgl1393DQg6EvjpdpFy2ZnzU6XUgZSzsC1clNz6COFIxv7kTM/L3QBJR9F+w5UgVofdK6J2zzobAjnJ35y40DNNIlXlL+buINL0mKLwcEkz6dGgAWiNsUGyNQG\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        // When
        CertificateDTO certificateDTO = underTest.getCertificate(jsonString);

        // Then
        assertEquals("353d4f18-4b78-b17c-5325-f92375cf40ec", certificateDTO.getId());
        assertEquals(2, certificateDTO.getChain().size());
        //assertEquals("intermediate", certificateDTO.getChain().get(0).getType());
        //assertEquals("root", certificateDTO.getChain().get(1).getType());
        assertNotNull(certificateDTO.getCert());
        assertNotNull(certificateDTO.getChain());
    }

    @Test
    public void getCertificateShouldThrowJsonResponseIncorrectException() throws JsonResponseIncorrectException {
        // Given
        String jsonString = "{\n" +
                "}";
        Exception exception = assertThrows(JsonResponseIncorrectException.class, () -> underTest.getCertificate(jsonString));
    }

    @Test
    public void getSignatureTest() throws JsonResponseIncorrectException {
        String json = "{\n" +
                "  \"signTime\": 12354567,\n" +
                "  \"signedHash\": \"v686SHskn4n/gDM0lLLzCRpKWbaKxZNGdtrNXncFVjM/EO+c7kudD/5ZlGuQPVgw1qK/QN/PUtdNl6LyIqI96UJ30czyoK96XoqNHOFxMsSZmoSzfzRqGhs9jayek4exTvJBs9UgdXamKi+1G/C56g9awtxydBpj2F2Iq+1BbCqOAEtx4PMo1+8syecmWg9cQMAU0skhG2Ve42d4xay3Mci3/QAiXUTpSRVW3EEvp9O+MQR9nl501VbBCU1cLuaA5Aa9JY13pHjvBMiGftC6R2/eJLG+hhcDzplC0Ni+GnXYpU0/b3ejhoHA2oU8IBXwcNnrkSXirmEneM6zqgAeQYwpAKFmhh9x37DbPunJflsf6lDYdQra2SqYZ2LkD9AIYBJZCEdAZGUtPCDWdVGHlfAAIA7hi63O6mXyhoUgSAELWV15zTo6i+JgfLjuw1UwqKSE6/RCuk6AY27LgvBdbEYq9tIwf9bqhMz8Dgse9gvslYheDTq+ZrWNEMzQ/U5a\",\n" +
                "  \"validUntil\": \"2030-11-23T18:25:43.511Z\",\n" +
                "  \"certificateId\": \"353d4f18-4b78-b17c-5325-f92375cf40ec\",\n" +
                "  \"signCertificate\": \"a68e1ae4-41ac-b140-ad1e-3219ff08a4e9\",\n" +
                "  \"signReturnCode\" : \"SUCCESS\",\n" +
                "  \"errorMessage\" : null\n" +
                "}";

        SignatureResponse signatureResponse = underTest.getSignature(json);
        assertFalse(underTest.isSignatureEmpty(signatureResponse));
        assertEquals(12354567, signatureResponse.getSignTime().longValue());
        assertEquals("v686SHskn4n/gDM0lLLzCRpKWbaKxZNGdtrNXncFVjM/EO+c7kudD/5ZlGuQPVgw1qK/QN/PUtdNl6LyIqI96UJ30czyoK96XoqNHOFxMsSZmoSzfzRqGhs9jayek4exTvJBs9UgdXamKi+1G/C56g9awtxydBpj2F2Iq+1BbCqOAEtx4PMo1+8syecmWg9cQMAU0skhG2Ve42d4xay3Mci3/QAiXUTpSRVW3EEvp9O+MQR9nl501VbBCU1cLuaA5Aa9JY13pHjvBMiGftC6R2/eJLG+hhcDzplC0Ni+GnXYpU0/b3ejhoHA2oU8IBXwcNnrkSXirmEneM6zqgAeQYwpAKFmhh9x37DbPunJflsf6lDYdQra2SqYZ2LkD9AIYBJZCEdAZGUtPCDWdVGHlfAAIA7hi63O6mXyhoUgSAELWV15zTo6i+JgfLjuw1UwqKSE6/RCuk6AY27LgvBdbEYq9tIwf9bqhMz8Dgse9gvslYheDTq+ZrWNEMzQ/U5a", signatureResponse.getSignedHash());
        assertEquals("2030-11-23T18:25:43.511Z", signatureResponse.getValidUntil());
        assertEquals("353d4f18-4b78-b17c-5325-f92375cf40ec", signatureResponse.getCertificateId());
        assertEquals("a68e1ae4-41ac-b140-ad1e-3219ff08a4e9", signatureResponse.getSignCertificate());
        assertEquals("SUCCESS", signatureResponse.getSignReturnCode());
        assertNull(signatureResponse.getErrorMessage());
    }

    @Test
    public void getSignatureShouldThrowJsonResponseIncorrectException() throws JsonResponseIncorrectException {
        // Given
        String jsonString = "{\n" +
                "}";
        Exception exception = assertThrows(JsonResponseIncorrectException.class, () -> underTest.getSignature(jsonString));
    }
}
