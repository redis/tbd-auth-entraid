package redis.clients.authentication.entraid;

import java.net.MalformedURLException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.IClientCredential;

import redis.clients.authentication.core.IdentityProvider;
import redis.clients.authentication.core.Token;

public final class EntraIDIdentityProvider implements IdentityProvider {

    private ConfidentialClientApplication app;
    private ClientCredentialParameters clientParams;

    public EntraIDIdentityProvider(String clientId, String authority, String secret,
            Set<String> scopes) {
        IClientCredential credential = ClientCredentialFactory.createFromSecret(secret);
        init(clientId, authority, credential, scopes);
    }

    public EntraIDIdentityProvider(String clientId, String authority, PrivateKey key, X509Certificate cert,
            Set<String> scopes) {
        IClientCredential credential = ClientCredentialFactory.createFromCertificate(key, cert);
        init(clientId, authority, credential, scopes);
    }

    protected void init(String clientId, String authority, IClientCredential credential, Set<String> scopes) {
        try {
            app = ConfidentialClientApplication.builder(clientId, credential).authority(authority).build();
        } catch (MalformedURLException e) {
            throw new RedisEntraIDException("Failed to init EntraID client!", e);
        }
        clientParams = ClientCredentialParameters.builder(scopes).build();
    }

    @Override
    public Token requestToken() {
        try {
            Future<IAuthenticationResult> tokenRequest = app.acquireToken(clientParams);
            return new JWToken(tokenRequest.get().accessToken());
        } catch (InterruptedException | ExecutionException e) {
            throw new RedisEntraIDException("Failed to acquire token!", e);
        }
    }
}
