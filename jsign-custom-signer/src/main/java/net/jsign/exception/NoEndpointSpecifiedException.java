package net.jsign.exception;

public class NoEndpointSpecifiedException extends Exception {
    public NoEndpointSpecifiedException(String message) {
        super(message);
    }

    public NoEndpointSpecifiedException(String message, Throwable cause) {
        super(message, cause);
    }
}
