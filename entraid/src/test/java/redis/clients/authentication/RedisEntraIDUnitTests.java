package redis.clients.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mockConstruction;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;
import org.mockito.MockedConstruction;

import redis.clients.authentication.core.IdentityProviderConfig;
import redis.clients.authentication.core.SimpleToken;
import redis.clients.authentication.core.TokenAuthConfig;
import redis.clients.authentication.entraid.EntraIDIdentityProvider;
import redis.clients.authentication.entraid.EntraIDTokenAuthConfigBuilder;
import redis.clients.authentication.entraid.ServicePrincipalInfo;
import redis.clients.jedis.DefaultJedisClientConfig;
import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.JedisPooled;

public class RedisEntraIDUnitTests {

    @Test
    public void testConfigBuilder() {
        String authority = "authority1";
        String clientId = "clientId1";
        String credential = "credential1";
        Set<String> scopes = Collections.singleton("scope1");
        IdentityProviderConfig config = EntraIDTokenAuthConfigBuilder.builder().authority(authority)
                .clientId(clientId).secret(credential).scopes(scopes).build()
                .getIdentityProviderConfig();

        assertNotNull(config);

        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
            EntraIDIdentityProvider.class, (mock, context) -> {
                ServicePrincipalInfo info = (ServicePrincipalInfo) context.arguments().get(0);
                assertEquals(clientId, info.getClientId());
                assertEquals(authority, info.getAuthority());
                assertEquals(credential, info.getSecret());
                assertEquals(scopes, context.arguments().get(1));

            })) {
            config.getProvider();
        }

        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
            EntraIDIdentityProvider.class, (mock, context) -> {
                assertNull(context.arguments().get(0));
                assertNull(context.arguments().get(1));
            })) {
            config.getProvider();
        }
    }

    @Test
    public void testJedisConfig() {
        TestContext testCtx = TestContext.DEFAULT;
        EndpointConfig endpointConfig = TestContext.getRedisEndpoint("standalone0");
        HostAndPort hnp = endpointConfig.getHostAndPort();

        TokenAuthConfig tokenAuthConfig = EntraIDTokenAuthConfigBuilder.builder()
                .authority(testCtx.getAuthority()).clientId(testCtx.getClientId())
                .secret(testCtx.getClientSecret()).scopes(testCtx.getRedisScopes()).build();

        DefaultJedisClientConfig jedisConfig = DefaultJedisClientConfig.builder()
                .tokenAuthConfig(tokenAuthConfig).build();

        AtomicInteger counter = new AtomicInteger(0);
        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
            EntraIDIdentityProvider.class, (mock, context) -> {
                ServicePrincipalInfo info = (ServicePrincipalInfo) context.arguments().get(0);
                assertEquals(testCtx.getClientId(), info.getClientId());
                assertEquals(testCtx.getAuthority(), info.getAuthority());
                assertEquals(testCtx.getClientSecret(), info.getSecret());
                assertEquals(testCtx.getRedisScopes(), context.arguments().get(1));
                assertNotNull(mock);
                doAnswer(invocation -> {
                    counter.incrementAndGet();
                    return new SimpleToken("token1", System.currentTimeMillis() + 5 * 60 * 1000,
                            System.currentTimeMillis(), Collections.singletonMap("oid", "default"));
                }).when(mock).requestToken();
            })) {
            JedisPooled jedis = new JedisPooled(hnp, jedisConfig);
            assertNotNull(jedis);
            assertEquals(1, counter.get());
        }
    }
}
