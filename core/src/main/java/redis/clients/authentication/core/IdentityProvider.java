package redis.clients.authentication.core;

public interface IdentityProvider {
    
    Token requestToken();
}