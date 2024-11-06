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
import redis.clients.authentication.entraid.EntraIDTokenAuthConfig;
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
        IdentityProviderConfig config = EntraIDTokenAuthConfig.builder().authority(authority).clientId(clientId)
                .secret(credential).scopes(scopes).build().getIdentityProviderConfig();

        assertNotNull(config);

        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
                EntraIDIdentityProvider.class, (mock, context) -> {
                    assertEquals(clientId, context.arguments().get(0));
                    assertEquals(authority, context.arguments().get(1));
                    assertEquals(credential, context.arguments().get(2));
                    assertEquals(scopes, context.arguments().get(3));

                })) {
            config.getProvider();
        }

        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
                EntraIDIdentityProvider.class, (mock, context) -> {
                    assertNull(context.arguments().get(0));
                    assertNull(context.arguments().get(1));
                    assertNull(context.arguments().get(2));
                    assertNull(context.arguments().get(3));

                })) {
            config.getProvider();
        }
    }

    @Test
    public void testJedisConfig() {
        TestContext testCtx = TestContext.DEFAULT;
        EndpointConfig endpointConfig = TestContext.getRedisEndpoint("standalone0");
        HostAndPort hnp = endpointConfig.getHostAndPort();

        TokenAuthConfig tokenAuthConfig = EntraIDTokenAuthConfig.builder()
                .authority(testCtx.getAuthority()).clientId(testCtx.getClientId())
                .secret(testCtx.getClientSecret()).scopes(testCtx.getRedisScopes())
                .build();

        DefaultJedisClientConfig jedisConfig = DefaultJedisClientConfig.builder()
                .tokenAuthConfig(tokenAuthConfig).build();

        AtomicInteger counter = new AtomicInteger(0);
        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
                EntraIDIdentityProvider.class, (mock, context) -> {
                    assertEquals(testCtx.getClientId(), context.arguments().get(0));
                    assertEquals(testCtx.getAuthority(), context.arguments().get(1));
                    assertEquals(testCtx.getClientSecret(), context.arguments().get(2));
                    assertEquals(testCtx.getRedisScopes(), context.arguments().get(3));
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
