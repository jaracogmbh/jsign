package net.jsign.exceptions;

public class NotABooleanValueException extends Exception{
    public NotABooleanValueException(String message) {
        super(message);
    }

    public NotABooleanValueException(String message, Throwable cause) {
        super(message, cause);
    }
}
