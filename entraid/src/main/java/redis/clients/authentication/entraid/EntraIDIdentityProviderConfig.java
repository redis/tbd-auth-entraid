/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.entraid;

import java.util.Set;
import java.util.function.Supplier;

import com.microsoft.aad.msal4j.IAuthenticationResult;

import redis.clients.authentication.core.IdentityProvider;
import redis.clients.authentication.core.IdentityProviderConfig;

public final class EntraIDIdentityProviderConfig implements IdentityProviderConfig {

    private final Supplier<IdentityProvider> providerSupplier;

    public EntraIDIdentityProviderConfig(ServicePrincipalInfo info, Set<String> scopes, int timeout) {
        providerSupplier = () -> new EntraIDIdentityProvider(info, scopes, timeout);
    }

    public EntraIDIdentityProviderConfig(ManagedIdentityInfo info, Set<String> scopes, int timeout) {
        providerSupplier = () -> new EntraIDIdentityProvider(info, scopes, timeout);
    }

    public EntraIDIdentityProviderConfig(
            Supplier<IAuthenticationResult> customEntraIdAuthenticationSupplier) {
        providerSupplier = () -> new EntraIDIdentityProvider(customEntraIdAuthenticationSupplier);
    }

    @Override
    public IdentityProvider getProvider() {
        IdentityProvider identityProvider = providerSupplier.get();
        return identityProvider;
    }
}
