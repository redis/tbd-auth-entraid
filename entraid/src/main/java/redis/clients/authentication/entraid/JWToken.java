/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.entraid;

import java.util.function.BiFunction;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWT;

import redis.clients.authentication.core.Token;

public class JWToken implements Token {
    private final String user;
    private final String token;
    private final long expiresAt;
    private final long receivedAt;
    private final BiFunction<String, Class<?>, ?> claimQuery;

    public JWToken(String token) {
        this.token = token;
        DecodedJWT jwt = JWT.decode(token);
        this.user = jwt.getClaim("oid").asString();
        this.expiresAt = jwt.getExpiresAt().getTime();
        this.receivedAt = System.currentTimeMillis();
        this.claimQuery = (key, clazz) -> jwt.getClaim(key).as(clazz);
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
    public String getUser() {
        return user;
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
    public <T> T tryGet(String key, Class<T> clazz) {
        return (T) claimQuery.apply(key, clazz);
    }

}
