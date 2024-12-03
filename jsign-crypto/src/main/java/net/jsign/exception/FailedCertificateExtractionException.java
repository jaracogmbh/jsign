package net.jsign.exception;

public class FailedCertificateExtractionException extends Exception {
    public FailedCertificateExtractionException(String message) {
        super(message);
    }

    public FailedCertificateExtractionException(String message, Throwable cause) {
        super(message, cause);
    }
}
