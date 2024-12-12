package redis.clients.authentication.core;

import java.util.Map;

public class SimpleToken implements Token {

    private String user;
    private String value;
    private long expiresAt;
    private long receivedAt;
    private Map<String, ?> claims;

    public SimpleToken(String user, String value, long expiresAt, long receivedAt,
            Map<String, ?> claims) {
        this.user = user;
        this.value = value;
        this.expiresAt = expiresAt;
        this.receivedAt = receivedAt;
        this.claims = claims;
    }

    @Override
    public String getUser() {
        return user;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public long getExpiresAt() {
        return expiresAt;
    }

    @Override
    public long getReceivedAt() {
        return receivedAt;
    }

    @Override
    public <T> T tryGet(String key, Class<T> clazz) {
        return (T) claims.get(key);
    }

    @Override
    public boolean isExpired() {
        return System.currentTimeMillis() > expiresAt;
    }

    @Override
    public long ttl() {
        return expiresAt - System.currentTimeMillis();
    }

}