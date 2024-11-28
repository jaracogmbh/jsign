package net.jsign.exception;

public class NotACorrectIntegerValueException extends Exception{
    public NotACorrectIntegerValueException(String message) {
        super(message);
    }

    public NotACorrectIntegerValueException(String message, Throwable cause) {
        super(message, cause);
    }
}
