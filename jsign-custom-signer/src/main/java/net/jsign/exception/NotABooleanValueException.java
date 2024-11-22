package net.jsign.exception;

public class NotABooleanValueException extends Exception{
    public NotABooleanValueException(String message) {
        super(message);
    }

    public NotABooleanValueException(String message, Throwable cause) {
        super(message, cause);
    }
}
