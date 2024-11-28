package net.jsign.exception;

public class NoPropertiesInPropertyFileException extends Exception{
    public NoPropertiesInPropertyFileException(String message) {
        super(message);
    }

    public NoPropertiesInPropertyFileException(String message, Throwable cause) {
        super(message, cause);
    }
}
