package redis.clients.authentication;

import static org.junit.Assert.assertNotNull;

import java.net.MalformedURLException;
import org.junit.Test;

import redis.clients.authentication.core.Token;
import redis.clients.authentication.entraid.EntraIDIdentityProvider;

public class RedisEntraIDIntegrationTests {

    @Test
    public void requestTokenWithSecret() throws MalformedURLException {
        TestContext testCtx = TestContext.DEFAULT;

        Token token = new EntraIDIdentityProvider(testCtx.getClientId(), testCtx.getAuthority(),
                testCtx.getClientSecret(), testCtx.getRedisScopes()).requestToken();

        assertNotNull(token.getValue());
    }

    @Test
    public void requestTokenWithCert() throws MalformedURLException {
        TestContext testCtx = TestContext.DEFAULT;

        Token token = new EntraIDIdentityProvider(testCtx.getClientId(), testCtx.getAuthority(),
                testCtx.getPrivateKey(), testCtx.getCert(), testCtx.getRedisScopes()).requestToken();

        assertNotNull(token.getValue());
    }
}
