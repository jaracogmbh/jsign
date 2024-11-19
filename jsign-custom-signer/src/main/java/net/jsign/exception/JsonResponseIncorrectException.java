package net.jsign.exception;

public class JsonResponseIncorrectException extends Exception {
    public JsonResponseIncorrectException(String message) {
        super(message);
    }

    public JsonResponseIncorrectException(String message, Throwable cause) {
        super(message, cause);
    }
}
