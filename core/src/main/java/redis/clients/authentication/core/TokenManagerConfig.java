/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.core;

/**
 * Token manager example configuration.
 */
public class TokenManagerConfig {

    private final float expirationRefreshRatio;
    private final int lowerRefreshBoundMillis;
    private final int tokenRequestExecTimeoutInMs;
    private final RetryPolicy retryPolicy;

    public static class RetryPolicy {
        private final int maxAttempts;
        private final int delayInMs;

        public RetryPolicy(int maxAttempts, int delayInMs) {
            this.maxAttempts = maxAttempts;
            this.delayInMs = delayInMs;
        }

        public int getMaxAttempts() {
            return maxAttempts;
        }

        public int getdelayInMs() {
            return delayInMs;
        }

    }

    public TokenManagerConfig(float expirationRefreshRatio, int lowerRefreshBoundMillis,
            int tokenRequestExecTimeoutInMs, RetryPolicy retryPolicy) {
        this.expirationRefreshRatio = expirationRefreshRatio;
        this.lowerRefreshBoundMillis = lowerRefreshBoundMillis;
        this.tokenRequestExecTimeoutInMs = tokenRequestExecTimeoutInMs;
        this.retryPolicy = retryPolicy;
    }

    /**
     * Represents the ratio of a token's lifetime at which a refresh should be triggered.
     * For example, a value of 0.75 means the token should be refreshed when 75% of its
     * lifetime has elapsed (or when 25% of its lifetime remains).
     */
    public float getExpirationRefreshRatio() {
        return expirationRefreshRatio;
    }

    /**
     * Represents the minimum time in milliseconds before token expiration to trigger a refresh, in milliseconds.
     * This value sets a fixed lower bound for when a token refresh should occur, regardless
     * of the token's total lifetime.
     * If set to 0 there will be no lower bound and the refresh will be triggered based on the expirationRefreshRatio only.
     */
    public int getLowerRefreshBoundMillis() {
        return lowerRefreshBoundMillis;
    }

    /**
     * Represents the maximum time in milliseconds to wait for a token request to complete.
     */
    public int getTokenRequestExecTimeoutInMs() {
        return tokenRequestExecTimeoutInMs;
    }

    /**
     * Represents the retry policy for token requests.
     */
    public RetryPolicy getRetryPolicy() {
        return retryPolicy;
    }
}
