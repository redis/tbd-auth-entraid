package redis.clients.authentication.entraid;

import redis.clients.authentication.core.AuthXException;

public class RedisEntraIDException extends AuthXException {

    public RedisEntraIDException(String message) {
        super(message);
    }

    public RedisEntraIDException(String message, Exception cause) {
        super(message, cause);
    }
}
