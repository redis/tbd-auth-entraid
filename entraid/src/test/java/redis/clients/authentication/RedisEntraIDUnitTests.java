package redis.clients.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.awaitility.Durations.*;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.both;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.awaitility.Awaitility;
import org.awaitility.Durations;
import org.junit.Test;
import org.mockito.MockedConstruction;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import redis.clients.authentication.core.IdentityProvider;
import redis.clients.authentication.core.IdentityProviderConfig;
import redis.clients.authentication.core.SimpleToken;
import redis.clients.authentication.core.Token;
import redis.clients.authentication.core.TokenAuthConfig;
import redis.clients.authentication.core.TokenListener;
import redis.clients.authentication.core.TokenManager;
import redis.clients.authentication.core.TokenManagerConfig;
import redis.clients.authentication.core.TokenRequestException;
import redis.clients.authentication.entraid.EntraIDIdentityProvider;
import redis.clients.authentication.entraid.EntraIDTokenAuthConfigBuilder;
import redis.clients.authentication.entraid.JWToken;
import redis.clients.authentication.entraid.ServicePrincipalInfo;
import redis.clients.jedis.DefaultJedisClientConfig;
import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.JedisPooled;

public class RedisEntraIDUnitTests {

    private static final float EXPIRATION_REFRESH_RATIO = 0.7F;
    private static final int LOWER_REFRESH_BOUND_MILLIS = 200;
    private static final int TOKEN_REQUEST_EXEC_TIMEOUT = 1000;
    private static final int RETRY_POLICY_MAX_ATTEMPTS = 5;
    private static final int RETRY_POLICY_DELAY = 100;

    private TokenManagerConfig tokenManagerConfig = new TokenManagerConfig(EXPIRATION_REFRESH_RATIO,
            LOWER_REFRESH_BOUND_MILLIS, TOKEN_REQUEST_EXEC_TIMEOUT,
            new TokenManagerConfig.RetryPolicy(RETRY_POLICY_MAX_ATTEMPTS, RETRY_POLICY_DELAY));

    private static final String TOKEN_VALUE = "tokenVal";
    private static final long TOKEN_EXPIRATION_TIME = System.currentTimeMillis() + 60 * 60 * 1000;
    private static final long TOKEN_ISSUE_TIME = System.currentTimeMillis();
    private static final String TOKEN_OID = "user1";

    private Token simpleToken = new SimpleToken(TOKEN_VALUE, TOKEN_EXPIRATION_TIME,
            TOKEN_ISSUE_TIME, Collections.singletonMap("oid", TOKEN_OID));

    private TestContext testCtx = TestContext.DEFAULT;

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
            JedisPooled jedis = new JedisPooled(new HostAndPort("localhost", 6379), jedisConfig);
            assertNotNull(jedis);
            assertEquals(1, counter.get());
        }
    }

    // T.1.2
    // Implement a stubbed IdentityProvider and verify that the TokenManager works normally and handles:
    // network errors or other exceptions thrown from the IdentityProvider
    // token parser errors
    // e.g missing ttl in IDP’s response
    // misformatted token
    @Test
    public void tokenRequestfailsWithException_fakeIdentityProviderTest() {

        IdentityProvider identityProvider = () -> {
            throw new RuntimeException("Test exception from identity provider!");
        };

        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);

        TokenRequestException e = assertThrows(TokenRequestException.class,
            () -> tokenManager.start(mock(TokenListener.class), true));

        assertEquals("Test exception from identity provider!",
            e.getCause().getCause().getMessage());
    }

    // T.2.1
    // Verify that the auth extension can obtain an initial token in a blocking manner from the identity provider.
    @Test
    public void initialTokenAcquisitionTest() {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean isTokenManagerStarted = new AtomicBoolean(false);
        IdentityProvider identityProvider = () -> {
            try {
                latch.await();
            } catch (InterruptedException e) {
            }
            return simpleToken;
        };

        TokenManagerConfig tokenManagerConfig = new TokenManagerConfig(EXPIRATION_REFRESH_RATIO,
                LOWER_REFRESH_BOUND_MILLIS, 60 * 60 * 1000,
                this.tokenManagerConfig.getRetryPolicy());

        TokenListener listener = mock(TokenListener.class);
        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);
        Thread thread = new Thread(() -> {
            try {
                tokenManager.start(listener, true);
                isTokenManagerStarted.set(true);
            } catch (Exception e) {
            }
        });
        thread.start();

        Awaitility.await().pollInterval(ONE_HUNDRED_MILLISECONDS).atMost(ONE_SECOND)
                .until(() -> Thread.State.WAITING == thread.getState());

        StackTraceElement[] stackTrace = thread.getStackTrace();
        assertEquals(false, isTokenManagerStarted.get());

        for (int i = 0; i < stackTrace.length; i++) {
            assertEquals(false, isTokenManagerStarted.get());

            if (stackTrace[i].getMethodName().equals("get")
                    && stackTrace[i + 1].getClassName().equals(TokenManager.class.getName())
                    && stackTrace[i + 1].getMethodName().equals("start")) {
                latch.countDown();
                break;
            }
        }
        assertEquals(0, latch.getCount());
        Awaitility.await().pollInterval(ONE_HUNDRED_MILLISECONDS).atMost(ONE_SECOND)
                .until(() -> isTokenManagerStarted.get());
        assertNotNull(tokenManager.getCurrentToken());
    }

    // T.2.1
    // Test the system's behavior when token acquisition fails initially but succeeds on retry.
    @Test
    public void tokenAcquisitionRetryTest() throws InterruptedException, TimeoutException {
        AtomicInteger numberOfRetries = new AtomicInteger(0);
        IdentityProvider identityProvider = () -> {
            if (numberOfRetries.incrementAndGet() < 3) {
                throw new RuntimeException("Test exception from identity provider!");
            }
            return simpleToken;

        };

        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);

        tokenManager.start(mock(TokenListener.class), false);

        Awaitility.await().pollInterval(ONE_HUNDRED_MILLISECONDS).atMost(ONE_SECOND)
                .until(() -> tokenManager.getCurrentToken() != null);
        assertEquals(3, numberOfRetries.get());
    }

    // T.2.1
    // Ensure the system handles timeouts during token acquisition gracefully.
    @Test
    public void tokenAcquisitionTimeoutTest() throws InterruptedException, TimeoutException {
        AtomicInteger numberOfRetries = new AtomicInteger(0);

        IdentityProvider identityProvider = () -> {
            if (numberOfRetries.getAndIncrement() < 1) {
                delay(TOKEN_REQUEST_EXEC_TIMEOUT);
            }
            return simpleToken;
        };

        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);

        tokenManager.start(mock(TokenListener.class), false);

        Awaitility.await().pollInterval(ONE_HUNDRED_MILLISECONDS).atMost(Durations.FIVE_SECONDS)
                .until(() -> tokenManager.getCurrentToken() != null);
        assertEquals(2, numberOfRetries.get());
    }

    // T.2.2
    // Verify that tokens are automatically renewed in the background and listeners are notified asynchronously without user intervention.
    @Test
    public void backgroundTokenRenewalTest() throws InterruptedException, TimeoutException {
        AtomicInteger numberOfTokens = new AtomicInteger(0);

        IdentityProvider identityProvider = () -> new SimpleToken(TOKEN_VALUE,
                System.currentTimeMillis() + 1000, System.currentTimeMillis(),
                Collections.singletonMap("oid", TOKEN_OID));

        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);
        TokenListener listener = new TokenListener() {
            @Override
            public void onTokenRenewed(Token token) {
                numberOfTokens.incrementAndGet();
            }

            @Override
            public void onError(Exception e) {
            }
        };

        tokenManager.start(listener, false);

        Awaitility.await().pollInterval(ONE_HUNDRED_MILLISECONDS).atMost(Durations.TWO_SECONDS)
                .until(() -> numberOfTokens.get(), is(2));
    }

    // T.2.2
    // Ensure the system propagates error during renewal back to the user
    @Test
    public void failedRenewalTest() {
        AtomicInteger numberOfErrors = new AtomicInteger(0);

        IdentityProvider identityProvider = () -> {
            throw new RuntimeException("Test exception from identity provider!");
        };

        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);
        TokenListener listener = new TokenListener() {
            @Override
            public void onTokenRenewed(Token token) {
            }

            @Override
            public void onError(Exception e) {
                numberOfErrors.incrementAndGet();
            }
        };

        tokenManager.start(listener, false);

        Awaitility.await().pollInterval(ONE_HUNDRED_MILLISECONDS).atMost(TWO_SECONDS)
                .until(() -> numberOfErrors.get(), is(1));
    }

    // T.2.3
    // Test that token renewal can be triggered at a specified percentage of the token's lifetime.
    @Test
    public void customRenewalTimingTest() {
        AtomicInteger numberOfTokens = new AtomicInteger(0);
        AtomicInteger timeDiff = new AtomicInteger(0);

        IdentityProvider identityProvider = () -> new SimpleToken(TOKEN_VALUE,
                System.currentTimeMillis() + 1000, System.currentTimeMillis(),
                Collections.singletonMap("oid", TOKEN_OID));

        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);
        TokenListener listener = new TokenListener() {
            Token lastToken = null;

            @Override
            public void onTokenRenewed(Token token) {
                numberOfTokens.incrementAndGet();
                if (lastToken != null) {
                    timeDiff.set((int) (token.getExpiresAt() - lastToken.getExpiresAt()));
                }
                lastToken = token;
            }

            @Override
            public void onError(Exception e) {
            }
        };

        tokenManager.start(listener, false);

        Integer lower = (int) (tokenManagerConfig.getExpirationRefreshRatio() * 1000 - 10);
        Integer upper = (int) (tokenManagerConfig.getExpirationRefreshRatio() * 1000 + 10);
        Awaitility.await().pollInterval(ONE_HUNDRED_MILLISECONDS).atMost(Durations.TWO_SECONDS)
                .until(() -> numberOfTokens.get(), is(2));
        assertThat((Integer) timeDiff.get(),
            both(greaterThanOrEqualTo(lower)).and(lessThanOrEqualTo(upper)));
    }

    // T.2.3
    // Verify behavior with edge case renewal timing configurations (e.g., very low or high percentages).
    @Test
    public void edgeCaseRenewalTimingTest() {
    }

    // T.2.4
    // Confirm that the system correctly identifies expired tokens. (isExpired works)
    @Test
    public void expiredTokenCheckTest() {
        String token = JWT.create().withExpiresAt(new Date(System.currentTimeMillis() - 1000))
                .withClaim("oid", "user1").sign(Algorithm.none());
        assertTrue(new JWToken(token).isExpired());

        token = JWT.create().withExpiresAt(new Date(System.currentTimeMillis() + 1000))
                .withClaim("oid", "user1").sign(Algorithm.none());
        assertFalse(new JWToken(token).isExpired());
    }

    // T.2.5
    // Verify that tokens are correctly parsed (e.g. with string value, expiresAt, and receivedAt attributes)
    @Test
    public void tokenParserTest() {
        long aSecondBefore = (System.currentTimeMillis() / 1000) * 1000 - 1000;

        String token = JWT.create().withExpiresAt(new Date(aSecondBefore)).withClaim("oid", "user1")
                .sign(Algorithm.none());
        Token actual = new JWToken(token);

        assertEquals(token, actual.getValue());
        assertEquals(aSecondBefore, actual.getExpiresAt());
        assertThat((Long) (System.currentTimeMillis() - actual.getReceivedAt()),
            lessThanOrEqualTo((Long) 10L));
    }

    // T.3.1
    // Verify that the most recent valid token is correctly cached and that the cache is initially empty
    @Test
    public void tokenCachingTest() {
        AtomicInteger numberOfRetries = new AtomicInteger(0);
        IdentityProvider identityProvider = () -> {
            if (numberOfRetries.getAndIncrement() < 1) {
                delay(TOKEN_REQUEST_EXEC_TIMEOUT);
            }
            return simpleToken;
        };
        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);
        assertNull(tokenManager.getCurrentToken());
        tokenManager.start(mock(TokenListener.class), true);
        assertNotNull(tokenManager.getCurrentToken());
    }

    private void delay(long durationInMs) {
        try {
            Thread.sleep(durationInMs);
        } catch (InterruptedException e) {
        }
    }
}
