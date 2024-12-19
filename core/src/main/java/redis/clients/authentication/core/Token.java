/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
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