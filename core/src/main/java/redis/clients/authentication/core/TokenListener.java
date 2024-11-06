package redis.clients.authentication.core;

public interface TokenListener {
    
    void onTokenRenewed(Token newToken);

    void onError(Exception reason);
}
