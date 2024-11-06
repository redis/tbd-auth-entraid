package redis.clients.authentication.entraid;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Set;

import redis.clients.authentication.core.IdentityProvider;
import redis.clients.authentication.core.IdentityProviderConfig;

public final class EntraIDIdentityProviderConfig implements IdentityProviderConfig, AutoCloseable {

    public enum EntraIDAccess {
        WithSecret,
        WithCert,
    }

    private String clientId;
    private EntraIDAccess accessWith;
    private String secret;
    private PrivateKey key;
    private X509Certificate cert;
    private String authority;
    private Set<String> scopes;

    public EntraIDIdentityProviderConfig(String clientId,
            EntraIDAccess accessWith,
            String secret,
            PrivateKey key,
            X509Certificate cert,
            String authority, Set<String> scopes) {
        this.clientId = clientId;
        this.accessWith = accessWith;
        this.secret = secret;
        this.key = key;
        this.cert = cert;
        this.authority = authority;
        this.scopes = scopes;
    }

    @Override
    public IdentityProvider getProvider() {
        IdentityProvider identityProvider = null;
        switch (accessWith) {
            case WithSecret:
                identityProvider = new EntraIDIdentityProvider(clientId, authority,
                        secret, scopes);
                break;
            case WithCert:
                identityProvider = new EntraIDIdentityProvider(clientId, authority,
                        key, cert, scopes);
                break;
            default:
                throw new RedisEntraIDException("Access type and credentials must be set!");
        }

        clear();
        return identityProvider;
    }

    @Override
    public void close() throws Exception {
        clear();
    }

    private void clear() {
        clientId = null;
        secret = null;
        key = null;
        cert = null;
        authority = null;
        scopes = null;
    }
}
