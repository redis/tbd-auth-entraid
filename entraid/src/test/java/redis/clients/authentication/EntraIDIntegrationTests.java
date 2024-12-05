package redis.clients.authentication;

import static org.junit.Assert.assertNotNull;

import java.net.MalformedURLException;
import org.junit.Test;
import redis.clients.authentication.core.Token;
import redis.clients.authentication.entraid.EntraIDIdentityProvider;
import redis.clients.authentication.entraid.ServicePrincipalInfo;

public class EntraIDIntegrationTests {

        @Test
        public void requestTokenWithSecret() throws MalformedURLException {
                TestContext testCtx = TestContext.DEFAULT;
                ServicePrincipalInfo servicePrincipalInfo = new ServicePrincipalInfo(
                                testCtx.getClientId(), testCtx.getClientSecret(),
                                testCtx.getAuthority());
                Token token = new EntraIDIdentityProvider(servicePrincipalInfo,
                                testCtx.getRedisScopes(),1000).requestToken();

                assertNotNull(token.getValue());
        }

        @Test
        public void requestTokenWithCert() throws MalformedURLException {
                TestContext testCtx = TestContext.DEFAULT;
                ServicePrincipalInfo servicePrincipalInfo = new ServicePrincipalInfo(
                                testCtx.getClientId(), testCtx.getPrivateKey(), testCtx.getCert(),
                                testCtx.getAuthority());
                Token token = new EntraIDIdentityProvider(servicePrincipalInfo,
                                testCtx.getRedisScopes(),1000).requestToken();
                assertNotNull(token.getValue());
        }

}
