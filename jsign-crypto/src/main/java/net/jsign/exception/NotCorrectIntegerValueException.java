package net.jsign.exception;

public class NotCorrectIntegerValueException extends Exception{
    public NotCorrectIntegerValueException(String message) {
        super(message);
    }

    public NotCorrectIntegerValueException(String message, Throwable cause) {
        super(message, cause);
    }
}
