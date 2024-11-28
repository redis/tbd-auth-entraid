package redis.clients.authentication.entraid;

import java.util.Set;

import redis.clients.authentication.core.IdentityProvider;
import redis.clients.authentication.core.IdentityProviderConfig;

public final class EntraIDIdentityProviderConfig implements IdentityProviderConfig, AutoCloseable {

    private ServicePrincipalInfo servicePrincipalInfo;
    private Set<String> scopes;
    private ManagedIdentityInfo managedIdentityInfo;

    public EntraIDIdentityProviderConfig(ServicePrincipalInfo servicePrincipalInfo,
            ManagedIdentityInfo info, Set<String> scopes) {
        this.servicePrincipalInfo = servicePrincipalInfo;
        this.scopes = scopes;
        this.managedIdentityInfo = info;
    }

    @Override
    public IdentityProvider getProvider() {
        IdentityProvider identityProvider = null;
        if (managedIdentityInfo != null) {
            identityProvider = new EntraIDIdentityProvider(managedIdentityInfo, scopes);
        } else {
            identityProvider = new EntraIDIdentityProvider(servicePrincipalInfo, scopes);
        }
        clear();
        return identityProvider;
    }

    @Override
    public void close() throws Exception {
        clear();
    }

    private void clear() {
        servicePrincipalInfo = null;
        managedIdentityInfo = null;
        scopes = null;
    }
}
