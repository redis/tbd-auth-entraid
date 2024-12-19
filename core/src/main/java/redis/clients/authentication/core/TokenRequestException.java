/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.core;

public class TokenRequestException extends AuthXException {

    private static final String msg = "Token request/renewal failed!";
    private final Exception identityProviderFailedWith;

    public TokenRequestException(Throwable cause, Exception identityProviderFailedWith) {
        super(getMessage(identityProviderFailedWith), cause);
        this.identityProviderFailedWith = identityProviderFailedWith;
    }

    public Exception getIdentityProviderFailedWith() {
        return identityProviderFailedWith;
    }

    private static String getMessage(Exception identityProviderFailedWith) {
        if (identityProviderFailedWith == null) {
            return msg;
        }
        return msg + " Identity provider request failed!"
                + identityProviderFailedWith.getMessage();
    }

}
