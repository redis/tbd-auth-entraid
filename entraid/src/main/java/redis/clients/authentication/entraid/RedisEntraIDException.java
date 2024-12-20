/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
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
