/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.core;

public interface TokenListener {
    
    void onTokenRenewed(Token newToken);

    void onError(Exception reason);
}
