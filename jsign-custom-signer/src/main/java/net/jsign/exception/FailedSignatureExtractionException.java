package net.jsign.exception;

public class FailedSignatureExtractionException extends Exception {
    public FailedSignatureExtractionException(String message) {
        super(message);
    }

    public FailedSignatureExtractionException(String message, Throwable cause) {
        super(message, cause);
    }
}
