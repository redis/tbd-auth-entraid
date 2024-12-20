/*
 * Copyright 2024, Redis Ltd. and Contributors All rights reserved. Licensed under the MIT License.
 */
package redis.clients.authentication.core;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class TokenManager {

    private TokenManagerConfig tokenManagerConfig;
    private TokenListener listener;
    private boolean stopped = false;
    private AtomicInteger numberOfRetries = new AtomicInteger(0);
    private Token currentToken = null;
    private AtomicBoolean started = new AtomicBoolean(false);
    private Dispatcher dispatcher;
    private RenewalScheduler renewalScheduler;
    private int retryDelay;
    private int maxRetries;

    public TokenManager(IdentityProvider identityProvider, TokenManagerConfig tokenManagerConfig) {
        this.tokenManagerConfig = tokenManagerConfig;
        maxRetries = tokenManagerConfig.getRetryPolicy().getMaxAttempts();
        retryDelay = tokenManagerConfig.getRetryPolicy().getdelayInMs();
        renewalScheduler = new RenewalScheduler(this::renewToken);
        dispatcher = new Dispatcher(identityProvider,
                tokenManagerConfig.getTokenRequestExecTimeoutInMs());
    }

    /**
     * Starts the token manager with given listener, blocks if blockForInitialToken is true
     * @param listener
     * @param blockForInitialToken
     */
    public void start(TokenListener listener, boolean blockForInitialToken) {
        if (!started.compareAndSet(false, true)) {
            throw new AuthXException("Token manager already started!");
        }
        this.listener = listener;
        RenewalTask currentTask = renewalScheduler.scheduleNext(0);
        if (blockForInitialToken) {
            try {
                renewalScheduler.waitFor(currentTask);
            } catch (Exception e) {
                throw prepareToPropogate(e);
            }
        }
    }

    /**
     * This method is called by the renewal scheduler
     * Dispatches a request to the identity provider asynchronously, with a timeout for execution, and returns the Token if successfully acquired.
     * If the request fails, it retries until the max number of retries is reached
     * If the request fails after max number of retries, it throws an exception
     * When a new Token is received, it schedules the next renewal with calculating the delay in respect to the new token.
     * Scheduling cycle only ends under two conditions:
     * 1. TokenManager is stopped
     * 2. Token renewal fails for max number of retries 
     * @return
     */
    protected Token renewToken() {
        if (stopped) {
            return null;
        }
        Token newToken = null;
        try {
            currentToken = newToken = dispatcher.requestTokenAsync().getResult();
            long delay = calculateRenewalDelay(newToken.getExpiresAt(), newToken.getReceivedAt());
            renewalScheduler.scheduleNext(delay);
            listener.onTokenRenewed(newToken);
            return newToken;
        } catch (Exception e) {
            if (numberOfRetries.getAndIncrement() < maxRetries) {
                renewalScheduler.scheduleNext(retryDelay);
            } else {
                RuntimeException propogateExc = prepareToPropogate(e);
                listener.onError(propogateExc);
                throw propogateExc;
            }
        }
        return null;
    }

    private RuntimeException prepareToPropogate(Exception e) {
        Throwable unwrapped = e;
        if (unwrapped instanceof ExecutionException) {
            unwrapped = e.getCause();
        }
        if (unwrapped instanceof TokenRequestException) {
            return (RuntimeException) unwrapped;
        }
        return new TokenRequestException(unwrapped, dispatcher.getError());
    }

    public TokenManagerConfig getConfig() {
        return tokenManagerConfig;
    }

    public Token getCurrentToken() {
        return currentToken;
    }

    public void stop() {
        stopped = true;
        renewalScheduler.stop();
        dispatcher.stop();
    }

    /**    
     * This method calculates the duration we need to wait for requesting the next token.
     * Token acquisition and authentication with the new token should be completed before the current token expires.
     * We define a time window between a point in time(T) and the token's expiration time. Let's call this the "renewal zone." 
     * The goal is to trigger a token renewal anytime soon within this renewal zone.
     * This is necessary to avoid situations where connections are running on an AUTH where token has already expired.
     * The method calculates the delay to the renewal zone based on two different strategies and returns the minimum of them.
     * If the calculated delay is somehow negative, it returns 0 to trigger the renewal immediately.
     * @param expireDate
     * @param issueDate
     * @return
     */
    public long calculateRenewalDelay(long expireDate, long issueDate) {
        long ttlLowerRefresh = ttlForLowerRefresh(expireDate);
        long ttlRatioRefresh = ttlForRatioRefresh(expireDate, issueDate);
        long delay = Math.min(ttlLowerRefresh, ttlRatioRefresh);

        return delay < 0 ? 0 : delay;
    }

    /**
     * This method calculates TTL to renewal zone based on a minimum duration to token expiration.
     * The suggested renewal zone here starts LowerRefreshBoundMillis(given in configuration) before the token expiration time.
     * As example we have 1 hour left to token expiration and LowerRefreshBoundMillis is configured as 10 minutes, renewal zone will start in 50 minutes from now.
     * This is the return value, 50 minutes TTL to renewal zone.
     * @param expireDate
     * @return
     */
    protected long ttlForLowerRefresh(long expireDate) {
        long startOfRenewalZone = expireDate - tokenManagerConfig.getLowerRefreshBoundMillis();
        return startOfRenewalZone - System.currentTimeMillis(); // TTL to renewal zone
    }

    /**
     * This method calculates TTL to renewal zone based on a ratio. 
     * The ExpirationRefreshRatio value in config, indicates the ratio of intended usage of token's total lifetime between receive/issue time and expiration time.
     * The suggested renewal zone here starts right after the token completes the given ratio of its total valid duration starting from issue time till expiration.
     * As example we have a token with 1 hour total valid time and it already reach to half life, which lefts 30 minutes to token expiration.
     * ExpirationRefreshRatio is configured as 0.8, means token will be in use for first 48 minutes of its valid duration. It needs to renew 12 minutes before the expiration. 
     * This makes it is 30 minutes left to expiration and 18 minutes left to renewal zone.
     * Return value is 18 minutes TTL to renewal zone.
     * @param expireDate
     * @param issueDate
     * @return
     */
    protected long ttlForRatioRefresh(long expireDate, long issueDate) {
        long totalLifetime = expireDate - issueDate;
        long intendedUsageDuration = (long) (totalLifetime
                * tokenManagerConfig.getExpirationRefreshRatio());
        long startOfRenewalZone = issueDate + intendedUsageDuration;
        return startOfRenewalZone - System.currentTimeMillis(); // TTL to renewal zone
    }
}
