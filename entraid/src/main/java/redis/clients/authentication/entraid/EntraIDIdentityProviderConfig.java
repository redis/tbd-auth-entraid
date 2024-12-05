package redis.clients.authentication.entraid;

import java.util.Set;
import java.util.function.Supplier;

import com.microsoft.aad.msal4j.IAuthenticationResult;

import redis.clients.authentication.core.IdentityProvider;
import redis.clients.authentication.core.IdentityProviderConfig;

public final class EntraIDIdentityProviderConfig implements IdentityProviderConfig, AutoCloseable {

    private Supplier<IdentityProvider> providerSupplier;

    public EntraIDIdentityProviderConfig(ServicePrincipalInfo info, Set<String> scopes) {
        providerSupplier = () -> new EntraIDIdentityProvider(info, scopes);
    }

    public EntraIDIdentityProviderConfig(ManagedIdentityInfo info, Set<String> scopes) {
        providerSupplier = () -> new EntraIDIdentityProvider(info, scopes);
    }

    public EntraIDIdentityProviderConfig(
            Supplier<IAuthenticationResult> customEntraIdAuthenticationSupplier) {
        providerSupplier = () -> new EntraIDIdentityProvider(customEntraIdAuthenticationSupplier);
    }

    @Override
    public IdentityProvider getProvider() {
        IdentityProvider identityProvider = providerSupplier.get();
        clear();
        return identityProvider;
    }

    @Override
    public void close() throws Exception {
        clear();
    }

    private void clear() {
        providerSupplier = null;
    }
}
