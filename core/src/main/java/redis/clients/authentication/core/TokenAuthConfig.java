/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.core;

public class TokenAuthConfig {

    private TokenManagerConfig tokenManagerConfig;
    private IdentityProviderConfig identityProviderConfig;

    public TokenAuthConfig(TokenManagerConfig tokenManagerConfig,
            IdentityProviderConfig identityProviderConfig) {
        this.tokenManagerConfig = tokenManagerConfig;
        this.identityProviderConfig = identityProviderConfig;
    }

    public TokenManagerConfig getTokenManagerConfig() {
        return tokenManagerConfig;
    }

    public IdentityProviderConfig getIdentityProviderConfig() {
        return identityProviderConfig;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder<T extends Builder<T>> {
        private IdentityProviderConfig identityProviderConfig;
        private int lowerRefreshBoundMillis;
        private float expirationRefreshRatio;
        private int tokenRequestExecTimeoutInMs;
        private int maxAttemptsToRetry;
        private int delayInMsToRetry;

        public T expirationRefreshRatio(float expirationRefreshRatio) {
            this.expirationRefreshRatio = expirationRefreshRatio;
            return (T) this;
        }

        public T lowerRefreshBoundMillis(int lowerRefreshBoundMillis) {
            this.lowerRefreshBoundMillis = lowerRefreshBoundMillis;
            return (T) this;
        }

        public T tokenRequestExecTimeoutInMs(int tokenRequestExecTimeoutInMs) {
            this.tokenRequestExecTimeoutInMs = tokenRequestExecTimeoutInMs;
            return (T) this;
        }

        public T maxAttemptsToRetry(int maxAttemptsToRetry) {
            this.maxAttemptsToRetry = maxAttemptsToRetry;
            return (T) this;
        }

        public T delayInMsToRetry(int delayInMsToRetry) {
            this.delayInMsToRetry = delayInMsToRetry;
            return (T) this;
        }

        public T identityProviderConfig(IdentityProviderConfig identityProviderConfig) {
            this.identityProviderConfig = identityProviderConfig;
            return (T) this;
        }

        public TokenAuthConfig build() {
            return new TokenAuthConfig(new TokenManagerConfig(expirationRefreshRatio,
                    lowerRefreshBoundMillis, tokenRequestExecTimeoutInMs,
                    new TokenManagerConfig.RetryPolicy(maxAttemptsToRetry, delayInMsToRetry)),
                    identityProviderConfig);
        }

        public static Builder from(Builder sample) {
            return new Builder().expirationRefreshRatio(sample.expirationRefreshRatio)
                    .lowerRefreshBoundMillis(sample.lowerRefreshBoundMillis)
                    .tokenRequestExecTimeoutInMs(sample.tokenRequestExecTimeoutInMs)
                    .maxAttemptsToRetry(sample.maxAttemptsToRetry)
                    .delayInMsToRetry(sample.delayInMsToRetry)
                    .identityProviderConfig(sample.identityProviderConfig);
        }
    }
}
