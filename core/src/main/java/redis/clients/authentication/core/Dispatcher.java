/*
 * Copyright 2024, Redis Ltd. and Contributors All rights reserved. Licensed under the MIT License.
 */
package redis.clients.authentication.core;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dispatches requests to the identity provider asynchronously with a timeout for the request execution.
 */
class Dispatcher {
    private ExecutorService executor = Executors.newFixedThreadPool(2);
    private Exception error;
    private long tokenRequestExecTimeoutInMs;
    private IdentityProvider identityProvider;
    private Logger logger = LoggerFactory.getLogger(getClass());

    public Dispatcher(IdentityProvider provider, long tokenRequestExecTimeoutInMs) {
        this.tokenRequestExecTimeoutInMs = tokenRequestExecTimeoutInMs;
        this.identityProvider = provider;
    }

    /**
     * Dispatches a request to the identity provider asynchronously 
     * with a timeout for the request execution and returns the request object
     * @return
     */
    public Request requestTokenAsync() {
        Future<Token> request = executor.submit(() -> requestToken());
        return () -> request.get(tokenRequestExecTimeoutInMs, TimeUnit.MILLISECONDS);
    }

    public Exception getError() {
        return error;
    }

    public void stop() {
        executor.shutdown();
    }

    /**
     * Makes the actual request to the identity provider
     * @return
     */
    private Token requestToken() {
        error = null;
        try {
            return identityProvider.requestToken();
        } catch (Exception e) {
            error = e;
            logger.error("Request to identity provider failed with message: " + e.getMessage(), e);
            throw e;
        }
    }
}
