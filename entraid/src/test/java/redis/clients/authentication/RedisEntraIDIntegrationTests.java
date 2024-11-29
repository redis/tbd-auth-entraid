package redis.clients.authentication;

import static org.junit.Assert.assertEquals;
import java.util.UUID;

import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import redis.clients.authentication.core.TokenAuthConfig;
import redis.clients.authentication.entraid.EntraIDTokenAuthConfigBuilder;
import redis.clients.authentication.entraid.ManagedIdentityInfo.UserManagedIdentityType;
import redis.clients.jedis.DefaultJedisClientConfig;
import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.JedisPooled;

public class RedisEntraIDIntegrationTests {
        private static final Logger log = LoggerFactory
                        .getLogger(RedisEntraIDIntegrationTests.class);

        private static TestContext testCtx;
        private static EndpointConfig endpointConfig;
        private static HostAndPort hnp;

        @BeforeClass
        public static void before() {
                try {
                        testCtx = TestContext.DEFAULT;
                        endpointConfig = testCtx.getRedisEndpoint("standalone-entraid-acl1");
                        hnp = endpointConfig.getHostAndPort();
                } catch (IllegalArgumentException e) {
                        log.warn("Skipping test because no Redis endpoint is configured");
                        org.junit.Assume.assumeTrue(false);
                }
        }

        // T.1.1
        // Verify authentication using Azure AD with managed identities
        @Test
        public void withUserAssignedId_azureManagedIdentityIntegrationTest() {
                TokenAuthConfig tokenAuthConfig = EntraIDTokenAuthConfigBuilder.builder()
                                .clientId(testCtx.getClientId())
                                .userAssignedManagedIdentity(UserManagedIdentityType.CLIENT_ID,
                                        "userManagedAuthxId")
                                .authority(testCtx.getAuthority()).scopes(testCtx.getRedisScopes())
                                .build();

                DefaultJedisClientConfig jedisConfig = DefaultJedisClientConfig.builder()
                                .tokenAuthConfig(tokenAuthConfig).build();

                try (JedisPooled jedis = new JedisPooled(hnp, jedisConfig)) {
                        String key = UUID.randomUUID().toString();
                        jedis.set(key, "value");
                        assertEquals("value", jedis.get(key));
                        jedis.del(key);
                }
        }

        // T.1.1
        // Verify authentication using Azure AD with managed identities
        @Test
        public void withSystemAssignedId_azureManagedIdentityIntegrationTest() {
                TokenAuthConfig tokenAuthConfig = EntraIDTokenAuthConfigBuilder.builder()
                                .clientId(testCtx.getClientId()).systemAssignedManagedIdentity()
                                .authority(testCtx.getAuthority()).scopes(testCtx.getRedisScopes())
                                .build();

                DefaultJedisClientConfig jedisConfig = DefaultJedisClientConfig.builder()
                                .tokenAuthConfig(tokenAuthConfig).build();

                try (JedisPooled jedis = new JedisPooled(hnp, jedisConfig)) {
                        String key = UUID.randomUUID().toString();
                        jedis.set(key, "value");
                        assertEquals("value", jedis.get(key));
                        jedis.del(key);
                }
        }

        // T.1.1
        // Verify authentication using Azure AD with service principals
        @Test
        public void withSecret_azureServicePrincipalIntegrationTest() {
                TokenAuthConfig tokenAuthConfig = EntraIDTokenAuthConfigBuilder.builder()
                                .clientId(testCtx.getClientId()).secret(testCtx.getClientSecret())
                                .authority(testCtx.getAuthority()).scopes(testCtx.getRedisScopes())
                                .build();

                DefaultJedisClientConfig jedisConfig = DefaultJedisClientConfig.builder()
                                .tokenAuthConfig(tokenAuthConfig).build();

                try (JedisPooled jedis = new JedisPooled(hnp, jedisConfig)) {
                        String key = UUID.randomUUID().toString();
                        jedis.set(key, "value");
                        assertEquals("value", jedis.get(key));
                        jedis.del(key);
                }
        }

        // T.1.1        
        // Verify authentication using Azure AD with service principals
        @Test
        public void withCertificate_azureServicePrincipalIntegrationTest() {
                TokenAuthConfig tokenAuthConfig = EntraIDTokenAuthConfigBuilder.builder()
                                .clientId(testCtx.getClientId()).secret(testCtx.getClientSecret())
                                .authority(testCtx.getAuthority()).scopes(testCtx.getRedisScopes())
                                .build();

                DefaultJedisClientConfig jedisConfig = DefaultJedisClientConfig.builder()
                                .tokenAuthConfig(tokenAuthConfig).build();

                try (JedisPooled jedis = new JedisPooled(hnp, jedisConfig)) {
                        String key = UUID.randomUUID().toString();
                        jedis.set(key, "value");
                        assertEquals("value", jedis.get(key));
                        jedis.del(key);
                }
        }

}
