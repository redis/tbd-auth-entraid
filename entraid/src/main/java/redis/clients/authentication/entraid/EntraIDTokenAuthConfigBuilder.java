package redis.clients.authentication.entraid;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.function.Supplier;

import com.microsoft.aad.msal4j.IAuthenticationResult;

import redis.clients.authentication.core.TokenAuthConfig;
import redis.clients.authentication.core.TokenManagerConfig;
import redis.clients.authentication.entraid.ManagedIdentityInfo.UserManagedIdentityType;
import redis.clients.authentication.entraid.ServicePrincipalInfo.ServicePrincipalAccess;

public class EntraIDTokenAuthConfigBuilder
        extends TokenAuthConfig.Builder<EntraIDTokenAuthConfigBuilder> implements AutoCloseable {
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
    private ServicePrincipalAccess accessWith;
    private ManagedIdentityInfo mii;
    private int tokenRequestExecTimeoutInMs;
    private Supplier<IAuthenticationResult> customEntraIdAuthenticationSupplier;

    public EntraIDTokenAuthConfigBuilder() {
        this.expirationRefreshRatio(DEFAULT_EXPIRATION_REFRESH_RATIO)
                .lowerRefreshBoundMillis(DEFAULT_LOWER_REFRESH_BOUND_MILLIS)
                .tokenRequestExecTimeoutInMs(DEFAULT_TOKEN_REQUEST_EXECUTION_TIMEOUT_IN_MS)
                .maxAttemptsToRetry(DEFAULT_MAX_ATTEMPTS_TO_RETRY)
                .delayInMsToRetry(DEFAULT_DELAY_IN_MS_TO_RETRY);
    }

    public EntraIDTokenAuthConfigBuilder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public EntraIDTokenAuthConfigBuilder secret(String secret) {
        this.secret = secret;
        this.accessWith = ServicePrincipalAccess.WithSecret;
        return this;
    }

    public EntraIDTokenAuthConfigBuilder key(PrivateKey key, X509Certificate cert) {
        this.key = key;
        this.cert = cert;
        this.accessWith = ServicePrincipalAccess.WithCert;
        return this;
    }

    public EntraIDTokenAuthConfigBuilder authority(String authority) {
        this.authority = authority;
        return this;
    }

    public EntraIDTokenAuthConfigBuilder systemAssignedManagedIdentity() {
        mii = new ManagedIdentityInfo();
        return this;
    }

    public EntraIDTokenAuthConfigBuilder userAssignedManagedIdentity(
            UserManagedIdentityType userManagedType, String id) {
        mii = new ManagedIdentityInfo(userManagedType, id);
        return this;
    }

    public EntraIDTokenAuthConfigBuilder customEntraIdAuthenticationSupplier(
            Supplier<IAuthenticationResult> customEntraIdAuthenticationSupplier) {
        this.customEntraIdAuthenticationSupplier = customEntraIdAuthenticationSupplier;
        return this;
    }

    public EntraIDTokenAuthConfigBuilder scopes(Set<String> scopes) {
        this.scopes = scopes;
        return this;
    }

    @Override
    public EntraIDTokenAuthConfigBuilder tokenRequestExecTimeoutInMs(
            int tokenRequestExecTimeoutInMs) {
        super.tokenRequestExecTimeoutInMs(tokenRequestExecTimeoutInMs);
        this.tokenRequestExecTimeoutInMs = tokenRequestExecTimeoutInMs;
        return this;
    }

    public TokenAuthConfig build() {
        ServicePrincipalInfo spi = null;
        if (key != null || cert != null || secret != null) {
            switch (accessWith) {
            case WithCert:
                spi = new ServicePrincipalInfo(clientId, key, cert, authority);
                break;
            case WithSecret:
                spi = new ServicePrincipalInfo(clientId, secret, authority);
                break;
            }
        }
        if (spi != null && mii != null) {
            throw new RedisEntraIDException(
                    "Cannot have both ServicePrincipal and ManagedIdentity!");
        }
        if (this.customEntraIdAuthenticationSupplier != null && (spi != null || mii != null)) {
            throw new RedisEntraIDException(
                    "Cannot have both customEntraIdAuthenticationSupplier and ServicePrincipal/ManagedIdentity!");
        }
        if (spi != null) {
            super.identityProviderConfig(
                new EntraIDIdentityProviderConfig(spi, scopes, tokenRequestExecTimeoutInMs));
        }
        if (mii != null) {
            super.identityProviderConfig(
                new EntraIDIdentityProviderConfig(mii, scopes, tokenRequestExecTimeoutInMs));
        }
        if (customEntraIdAuthenticationSupplier != null) {
            super.identityProviderConfig(
                new EntraIDIdentityProviderConfig(customEntraIdAuthenticationSupplier));
        }
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
        customEntraIdAuthenticationSupplier = null;
    }

    public static EntraIDTokenAuthConfigBuilder builder() {
        return new EntraIDTokenAuthConfigBuilder();
    }

    public static EntraIDTokenAuthConfigBuilder from(EntraIDTokenAuthConfigBuilder sample) {
        TokenAuthConfig tokenAuthConfig = TokenAuthConfig.Builder.from(sample).build();
        TokenManagerConfig tokenManagerConfig = tokenAuthConfig.getTokenManagerConfig();

        EntraIDTokenAuthConfigBuilder builder = (EntraIDTokenAuthConfigBuilder) new EntraIDTokenAuthConfigBuilder()
                .expirationRefreshRatio(tokenManagerConfig.getExpirationRefreshRatio())
                .lowerRefreshBoundMillis(tokenManagerConfig.getLowerRefreshBoundMillis())
                .tokenRequestExecTimeoutInMs(tokenManagerConfig.getTokenRequestExecTimeoutInMs())
                .maxAttemptsToRetry(tokenManagerConfig.getRetryPolicy().getMaxAttempts())
                .delayInMsToRetry(tokenManagerConfig.getRetryPolicy().getdelayInMs())
                .identityProviderConfig(tokenAuthConfig.getIdentityProviderConfig());

        builder.accessWith = sample.accessWith;
        builder.authority = sample.authority;
        builder.cert = sample.cert;
        builder.clientId = sample.clientId;
        builder.customEntraIdAuthenticationSupplier = sample.customEntraIdAuthenticationSupplier;
        builder.key = sample.key;
        builder.mii = sample.mii;
        builder.scopes = sample.scopes;
        builder.secret = sample.secret;
        return builder;
    }
}
