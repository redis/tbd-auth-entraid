package redis.clients.authentication.core;

import java.util.Map;

public class SimpleToken implements Token {

    private String value;
    private long expiresAt;
    private long receivedAt;
    private Map<String, String> claims;

    public SimpleToken(String value, long expiresAt, long receivedAt, Map<String, String> claims) {
        this.value = value;
        this.expiresAt = expiresAt;
        this.receivedAt = receivedAt;
        this.claims = claims;
    }

    @Override
    public boolean isExpired() {
        return System.currentTimeMillis() > expiresAt;
    }

    @Override
    public long ttl() {
        return expiresAt - System.currentTimeMillis();
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
    public String tryGet(String key) {
        return claims.get(key);
    }
}