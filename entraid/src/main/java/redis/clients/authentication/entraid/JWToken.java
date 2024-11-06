package redis.clients.authentication.entraid;

import java.util.function.Function;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWT;

import redis.clients.authentication.core.Token;

public class JWToken implements Token {
    private final String token;
    private final long expiresAt;
    private final long receivedAt;
    private final Function<String, String> claimQuery;

    public JWToken(String token) {
        this.token = token;
        DecodedJWT jwt = JWT.decode(token);
        this.expiresAt = jwt.getExpiresAt().getTime();
        this.receivedAt = System.currentTimeMillis();
        this.claimQuery = key -> jwt.getClaim(key).asString();
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
        return token;
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
    public String toString() {
        return token;
    }

    @Override
    public int hashCode() {
        return token.hashCode();
    }

    @Override
    public boolean equals(Object that) {
        if (this == that) return true;
        if (that == null) return false;
        if (that instanceof Token) {
            return token.equals(((Token) that).getValue());
        }
        return token.equals(that);
    }

    @Override
    public String tryGet(String key) {
        return claimQuery.apply(key);
    }
}
