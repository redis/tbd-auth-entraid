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

    public static class Builder {
        private IdentityProviderConfig identityProviderConfig;
        private int lowerRefreshBoundMillis;
        private float expirationRefreshRatio;
        private int tokenRequestExecTimeoutInMs;
        private int maxAttemptsToRetry;
        private int delayInMsToRetry;

        public Builder expirationRefreshRatio(float expirationRefreshRatio) {
            this.expirationRefreshRatio = expirationRefreshRatio;
            return this;
        }

        public Builder lowerRefreshBoundMillis(int lowerRefreshBoundMillis) {
            this.lowerRefreshBoundMillis = lowerRefreshBoundMillis;
            return this;
        }

        public Builder tokenRequestExecTimeoutInMs(int tokenRequestExecTimeoutInMs) {
            this.tokenRequestExecTimeoutInMs = tokenRequestExecTimeoutInMs;
            return this;
        }

        public Builder maxAttemptsToRetry(int maxAttemptsToRetry) {
            this.maxAttemptsToRetry = maxAttemptsToRetry;
            return this;
        }

        public Builder delayInMsToRetry(int delayInMsToRetry) {
            this.delayInMsToRetry = delayInMsToRetry;
            return this;
        }

        public Builder identityProviderConfig(IdentityProviderConfig identityProviderConfig) {
            this.identityProviderConfig = identityProviderConfig;
            return this;
        }

        public TokenAuthConfig build() {
            return new TokenAuthConfig(new TokenManagerConfig(expirationRefreshRatio,
                    lowerRefreshBoundMillis, tokenRequestExecTimeoutInMs,
                    new TokenManagerConfig.RetryPolicy(maxAttemptsToRetry, delayInMsToRetry)),
                    identityProviderConfig);
        }
    }
}
