package redis.clients.authentication.core;

public interface Token {

    public boolean isExpired();

    public long ttl();

    public String getValue();

    public long getExpiresAt();

    public long getReceivedAt();

    public String tryGet(String key);
}