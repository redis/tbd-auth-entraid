package redis.clients.authentication.entraid;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Set;

import redis.clients.authentication.core.TokenAuthConfig;

public class EntraIDTokenAuthConfig {

    private EntraIDTokenAuthConfig() {
    }

    public static class Builder extends TokenAuthConfig.Builder implements AutoCloseable {
        public static final float DEFAULT_EXPIRATION_REFRESH_RATIO = 0.8F;
        public static final int DEFAULT_LOWER_REFRESH_BOUND_MILLIS = 2 * 60 * 1000;
        public static final int DEFAULT_TOKEN_REQUEST_EXECUTION_TIMEOUT_IN_MS = 1000;
        public static final int DEFAULT_MAX_ATTEMPTS_TO_RETRY = 5;
        public static final int DEFAULT_DELAY_IN_MS_TO_RETRY = 100;

        private String clientId;
        private String secret;
        private PrivateKey key;
        private X509Certificate cert;
        private String authority;
        private Set<String> scopes;
        private EntraIDIdentityProviderConfig.EntraIDAccess accessWith;

        public Builder() {
            this.expirationRefreshRatio(DEFAULT_EXPIRATION_REFRESH_RATIO)
                    .lowerRefreshBoundMillis(DEFAULT_LOWER_REFRESH_BOUND_MILLIS)
                    .tokenRequestExecTimeoutInMs(DEFAULT_TOKEN_REQUEST_EXECUTION_TIMEOUT_IN_MS)
                    .maxAttemptsToRetry(DEFAULT_MAX_ATTEMPTS_TO_RETRY)
                    .delayInMsToRetry(DEFAULT_DELAY_IN_MS_TO_RETRY);
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder secret(String secret) {
            this.secret = secret;
            this.accessWith = EntraIDIdentityProviderConfig.EntraIDAccess.WithSecret;
            return this;
        }

        public Builder key(PrivateKey key, X509Certificate cert) {
            this.key = key;
            this.accessWith = EntraIDIdentityProviderConfig.EntraIDAccess.WithCert;
            return this;
        }

        public Builder authority(String authority) {
            this.authority = authority;
            return this;
        }

        public Builder scopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public TokenAuthConfig build() {
            EntraIDIdentityProviderConfig idProviderConfig = new EntraIDIdentityProviderConfig(clientId, accessWith,
                    secret, key, cert, authority, scopes);
            super.identityProviderConfig(idProviderConfig);
            return super.build();
        }

        @Override
        public void close() throws Exception {
            clientId = null;
            secret = null;
            key = null;
            cert = null;
            authority = null;
            scopes = null;
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
