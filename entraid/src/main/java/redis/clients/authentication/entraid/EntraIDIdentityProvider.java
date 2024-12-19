/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.entraid;

import java.net.MalformedURLException;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.function.Supplier;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.IClientCredential;
import com.microsoft.aad.msal4j.ManagedIdentityApplication;
import com.microsoft.aad.msal4j.ManagedIdentityParameters;
import redis.clients.authentication.core.IdentityProvider;
import redis.clients.authentication.core.Token;

public final class EntraIDIdentityProvider implements IdentityProvider {

    private Supplier<IAuthenticationResult> resultSupplier;

    public EntraIDIdentityProvider(ServicePrincipalInfo servicePrincipalInfo, Set<String> scopes,
            int timeout) {
        IClientCredential credential = getClientCredential(servicePrincipalInfo);
        ConfidentialClientApplication app;

        try {
            String authority = servicePrincipalInfo.getAuthority();
            authority = authority == null ? ConfidentialClientApplication.DEFAULT_AUTHORITY
                    : authority;
            app = ConfidentialClientApplication
                    .builder(servicePrincipalInfo.getClientId(), credential).authority(authority)
                    .readTimeoutForDefaultHttpClient(timeout).build();
        } catch (MalformedURLException e) {
            throw new RedisEntraIDException("Failed to init EntraID client!", e);
        }
        ClientCredentialParameters params = ClientCredentialParameters.builder(scopes)
                .skipCache(true).build();

        resultSupplier = () -> supplierForConfidentialApp(app, params);
    }

    public EntraIDIdentityProvider(ManagedIdentityInfo info, Set<String> scopes, int timeout) {
        ManagedIdentityApplication app = ManagedIdentityApplication.builder(info.getId())
                .readTimeoutForDefaultHttpClient(timeout).build();

        ManagedIdentityParameters params = ManagedIdentityParameters
                .builder(scopes.iterator().next()).forceRefresh(true).build();
        resultSupplier = () -> supplierForManagedIdentityApp(app, params);
    }

    public EntraIDIdentityProvider(
            Supplier<IAuthenticationResult> customEntraIdAuthenticationSupplier) {
        this.resultSupplier = customEntraIdAuthenticationSupplier;
    }

    private IClientCredential getClientCredential(ServicePrincipalInfo servicePrincipalInfo) {
        switch (servicePrincipalInfo.getAccessWith()) {
        case WithSecret:
            return ClientCredentialFactory.createFromSecret(servicePrincipalInfo.getSecret());
        case WithCert:
            return ClientCredentialFactory.createFromCertificate(servicePrincipalInfo.getKey(),
                servicePrincipalInfo.getCert());
        default:
            throw new RedisEntraIDException("Invalid ServicePrincipalAccess type!");
        }
    }

    @Override
    public Token requestToken() {
        return new JWToken(resultSupplier.get().accessToken());
    }

    public IAuthenticationResult supplierForConfidentialApp(ConfidentialClientApplication app,
            ClientCredentialParameters params) {
        try {
            Future<IAuthenticationResult> tokenRequest = app.acquireToken(params);
            return tokenRequest.get();
        } catch (InterruptedException | ExecutionException e) {
            throw new RedisEntraIDException("Failed to acquire token!", e);
        }
    }

    public IAuthenticationResult supplierForManagedIdentityApp(ManagedIdentityApplication app,
            ManagedIdentityParameters params) {
        try {
            Future<IAuthenticationResult> tokenRequest = app.acquireTokenForManagedIdentity(params);
            return tokenRequest.get();
        } catch (Exception e) {
            throw new RedisEntraIDException("Failed to acquire token!", e);
        }
    }
}
