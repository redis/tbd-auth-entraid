package redis.clients.authentication.core;

public interface Token {

    public String getUser();

    public String getValue();

    public long getExpiresAt();

    public long getReceivedAt();

    public boolean isExpired();

    public long ttl();

    public <T> T tryGet(String key, Class<T> clazz);

}