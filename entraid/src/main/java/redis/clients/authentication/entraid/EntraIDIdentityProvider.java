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

    private interface ClientApp {
        public IAuthenticationResult request();
    }

    private interface ClientAppFactory {
        public ClientApp create();
    }

    private ClientAppFactory clientAppFactory;
    private ClientApp clientApp;

    public EntraIDIdentityProvider(ServicePrincipalInfo servicePrincipalInfo, Set<String> scopes,
            int timeout) {

        clientAppFactory = () -> {
            return createConfidentialClientApp(servicePrincipalInfo, scopes, timeout);
        };
    }

    private ClientApp createConfidentialClientApp(ServicePrincipalInfo servicePrincipalInfo,
            Set<String> scopes, int timeout) {
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

        return () -> requestWithConfidentialClient(app, params);
    }

    public EntraIDIdentityProvider(ManagedIdentityInfo info, Set<String> scopes, int timeout) {

        clientAppFactory = () -> {
            return createManagedIdentityApp(info, scopes, timeout);
        };
    }

    private ClientApp createManagedIdentityApp(ManagedIdentityInfo info, Set<String> scopes,
            int timeout) {
        ManagedIdentityApplication app = ManagedIdentityApplication.builder(info.getId())
                .readTimeoutForDefaultHttpClient(timeout).build();

        ManagedIdentityParameters params = ManagedIdentityParameters
                .builder(scopes.iterator().next()).forceRefresh(true).build();
        return () -> requestWithManagedIdentity(app, params);
    }

    public EntraIDIdentityProvider(
            Supplier<IAuthenticationResult> customEntraIdAuthenticationSupplier) {

        clientAppFactory = () -> {
            return () -> customEntraIdAuthenticationSupplier.get();
        };
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
        clientApp = clientApp == null ? clientAppFactory.create() : clientApp;
        return new JWToken(clientApp.request().accessToken());
    }

    public IAuthenticationResult requestWithConfidentialClient(ConfidentialClientApplication app,
            ClientCredentialParameters params) {
        try {
            Future<IAuthenticationResult> tokenRequest = app.acquireToken(params);
            return tokenRequest.get();
        } catch (InterruptedException | ExecutionException e) {
            throw new RedisEntraIDException("Failed to acquire token!", e);
        }
    }

    public IAuthenticationResult requestWithManagedIdentity(ManagedIdentityApplication app,
            ManagedIdentityParameters params) {
        try {
            Future<IAuthenticationResult> tokenRequest = app.acquireTokenForManagedIdentity(params);
            return tokenRequest.get();
        } catch (Exception e) {
            throw new RedisEntraIDException("Failed to acquire token!", e);
        }
    }
}
