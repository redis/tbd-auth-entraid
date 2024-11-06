package redis.clients.authentication.core;

public class AuthXException extends RuntimeException {

    public AuthXException(String message) {
        super(message);
    }

    public AuthXException(String message, Throwable cause) {
        super(message, cause);
    }
}
