/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.core;

public class AuthXException extends RuntimeException {

    public AuthXException(String message) {
        super(message);
    }

    public AuthXException(String message, Throwable cause) {
        super(message, cause);
    }
}
