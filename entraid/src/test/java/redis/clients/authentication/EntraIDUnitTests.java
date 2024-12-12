package redis.clients.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.awaitility.Durations.*;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.both;
import static org.hamcrest.MatcherAssert.assertThat;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import org.awaitility.Awaitility;
import org.awaitility.Durations;
import org.junit.Test;
import org.mockito.MockedConstruction;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.IClientSecret;
import com.microsoft.aad.msal4j.ManagedIdentityId;

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
import redis.clients.authentication.entraid.ManagedIdentityInfo;
import redis.clients.authentication.entraid.ServicePrincipalInfo;
import redis.clients.authentication.entraid.ManagedIdentityInfo.UserManagedIdentityType;

// import redis.clients.jedis.DefaultJedisClientConfig;
// import redis.clients.jedis.HostAndPort;
// import redis.clients.jedis.JedisPooled;

public class EntraIDUnitTests {

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

    private Token simpleToken = new SimpleToken(TOKEN_OID, TOKEN_VALUE, TOKEN_EXPIRATION_TIME,
            TOKEN_ISSUE_TIME, null);

    private TestContext testCtx = TestContext.DEFAULT;

    @Test
    public void testConfigBuilder() {
        String authority = "authority1";
        String clientId = "clientId1";
        String credential = "credential1";
        Set<String> scopes = Collections.singleton("scope1");
        IdentityProviderConfig configWithSecret = EntraIDTokenAuthConfigBuilder.builder()
                .authority(authority).clientId(clientId).secret(credential).scopes(scopes).build()
                .getIdentityProviderConfig();
        assertNotNull(configWithSecret);
        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
            EntraIDIdentityProvider.class, (mock, context) -> {
                ServicePrincipalInfo info = (ServicePrincipalInfo) context.arguments().get(0);
                assertEquals(clientId, info.getClientId());
                assertEquals(authority, info.getAuthority());
                assertEquals(credential, info.getSecret());
                assertEquals(scopes, context.arguments().get(1));

            })) {
            configWithSecret.getProvider();
        }

        IdentityProviderConfig configWithCert = EntraIDTokenAuthConfigBuilder.builder()
                .authority(authority).clientId(clientId)
                .key(testCtx.getPrivateKey(), testCtx.getCert()).scopes(scopes).build()
                .getIdentityProviderConfig();
        assertNotNull(configWithCert);
        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
            EntraIDIdentityProvider.class, (mock, context) -> {
                ServicePrincipalInfo info = (ServicePrincipalInfo) context.arguments().get(0);
                assertEquals(clientId, info.getClientId());
                assertEquals(authority, info.getAuthority());
                assertEquals(testCtx.getPrivateKey(), info.getKey());
                assertEquals(testCtx.getCert(), info.getCert());
                assertEquals(scopes, context.arguments().get(1));

            })) {
            configWithCert.getProvider();
        }

        IdentityProviderConfig configWithManagedId = EntraIDTokenAuthConfigBuilder.builder()
                .systemAssignedManagedIdentity().scopes(scopes).build().getIdentityProviderConfig();
        assertNotNull(configWithManagedId);
        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
            EntraIDIdentityProvider.class, (mock, context) -> {
                ManagedIdentityInfo info = (ManagedIdentityInfo) context.arguments().get(0);
                assertEquals(ManagedIdentityId.systemAssigned().getIdType(),
                    info.getId().getIdType());
                assertEquals(scopes, context.arguments().get(1));
            })) {
            configWithManagedId.getProvider();
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

        assertEquals("Test exception from identity provider!", e.getCause().getMessage());
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
                delay(TOKEN_REQUEST_EXEC_TIMEOUT * 2);
            }
            return simpleToken;
        };

        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);

        long startTime = System.currentTimeMillis();
        tokenManager.start(mock(TokenListener.class), false);

        Awaitility.await().pollInterval(ONE_HUNDRED_MILLISECONDS).atMost(Durations.FIVE_SECONDS)
                .until(() -> tokenManager.getCurrentToken() != null);
        assertEquals(2, numberOfRetries.get());
        long totalTime = System.currentTimeMillis() - startTime;
        assertThat(totalTime, lessThan(TOKEN_REQUEST_EXEC_TIMEOUT * 2L));
    }

    // T.2.2
    // Verify that tokens are automatically renewed in the background and listeners are notified asynchronously without user intervention.
    @Test
    public void backgroundTokenRenewalTest() throws InterruptedException, TimeoutException {
        AtomicInteger numberOfTokens = new AtomicInteger(0);

        IdentityProvider identityProvider = () -> new SimpleToken(TOKEN_OID, TOKEN_VALUE,
                System.currentTimeMillis() + 1000, System.currentTimeMillis(), null);

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
    // T.4.1
    // Verify that token renewal timing can be configured correctly.
    @Test
    public void customRenewalTimingTest() {
        AtomicInteger numberOfTokens = new AtomicInteger(0);
        AtomicInteger timeDiff = new AtomicInteger(0);

        IdentityProvider identityProvider = () -> new SimpleToken(TOKEN_OID, TOKEN_VALUE,
                System.currentTimeMillis() + 1000, System.currentTimeMillis(), null);

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
    // T.4.1
    // Verify that token renewal timing can be configured correctly.
    @Test
    public void highPercentage_edgeCaseRenewalTimingTest() {
        List<Token> tokens = new ArrayList<Token>();
        int validDurationInMs = 1000;

        IdentityProvider identityProvider = () -> new SimpleToken(TOKEN_OID, TOKEN_VALUE,
                System.currentTimeMillis() + validDurationInMs, System.currentTimeMillis(), null);

        TokenManagerConfig tokenManagerConfig = new TokenManagerConfig(0.99F, 0,
                TOKEN_REQUEST_EXEC_TIMEOUT,
                new TokenManagerConfig.RetryPolicy(RETRY_POLICY_MAX_ATTEMPTS, RETRY_POLICY_DELAY));

        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);
        TokenListener listener = new TokenListener() {

            @Override
            public void onTokenRenewed(Token token) {
                tokens.add(token);
            }

            @Override
            public void onError(Exception e) {
            }
        };

        tokenManager.start(listener, false);

        Awaitility.await().pollInterval(Duration.ofMillis(10)).atMost(Durations.TWO_SECONDS)
                .until(() -> tokens.size(), is(2));

        Token initialToken = tokens.get(0);
        Token secondToken = tokens.get(1);
        Long renewalWindowStart = initialToken.getReceivedAt()
                + (long) (validDurationInMs * tokenManagerConfig.getExpirationRefreshRatio());
        Long renewalWindowEnd = initialToken.getExpiresAt();
        assertThat((Long) secondToken.getReceivedAt(),
            both(greaterThanOrEqualTo(renewalWindowStart))
                    .and(lessThanOrEqualTo(renewalWindowEnd)));
    }

    // T.2.3
    // Verify behavior with edge case renewal timing configurations (e.g., very low or high percentages).
    // T.4.1
    // Verify that token renewal timing can be configured correctly.
    @Test
    public void lowPercentage_edgeCaseRenewalTimingTest() {
        List<Token> tokens = new ArrayList<Token>();
        int validDurationInMs = 1000;

        IdentityProvider identityProvider = () -> new SimpleToken(TOKEN_OID, TOKEN_VALUE,
                System.currentTimeMillis() + validDurationInMs, System.currentTimeMillis(), null);

        TokenManagerConfig tokenManagerConfig = new TokenManagerConfig(0.01F, 0,
                TOKEN_REQUEST_EXEC_TIMEOUT,
                new TokenManagerConfig.RetryPolicy(RETRY_POLICY_MAX_ATTEMPTS, RETRY_POLICY_DELAY));

        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);
        TokenListener listener = new TokenListener() {

            @Override
            public void onTokenRenewed(Token token) {
                tokens.add(token);
            }

            @Override
            public void onError(Exception e) {
            }
        };

        tokenManager.start(listener, false);

        Awaitility.await().pollInterval(ONE_MILLISECOND).atMost(Durations.TWO_SECONDS)
                .until(() -> tokens.size(), is(2));

        Token initialToken = tokens.get(0);
        Token secondToken = tokens.get(1);
        Long renewalWindowStart = initialToken.getReceivedAt()
                + (long) (validDurationInMs * tokenManagerConfig.getExpirationRefreshRatio());
        Long renewalWindowEnd = initialToken.getExpiresAt();
        assertThat((Long) secondToken.getReceivedAt(),
            both(greaterThanOrEqualTo(renewalWindowStart))
                    .and(lessThanOrEqualTo(renewalWindowEnd)));
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

    // T.2.5
    // Ensure that token objects are immutable and cannot be modified after creation.
    @Test
    public void tokenImmutabilityTest() {
        // TODO :  what is expected exatcly ?
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

    // T.3.1
    // Ensure the token cache is updated when a new token is acquired or renewed.
    @Test
    public void cacheUpdateOnRenewalTest() {

        AtomicInteger numberOfTokens = new AtomicInteger(0);
        IdentityProvider identityProvider = () -> {
            return new SimpleToken("user1", "" + numberOfTokens.incrementAndGet(),
                    System.currentTimeMillis() + 500, System.currentTimeMillis(), null);
        };
        TokenManager tokenManager = new TokenManager(identityProvider, tokenManagerConfig);
        assertNull(tokenManager.getCurrentToken());
        tokenManager.start(mock(TokenListener.class), true);
        assertNotNull(tokenManager.getCurrentToken());
        assertEquals("1", tokenManager.getCurrentToken().getValue());
        Awaitility.await().pollInterval(ONE_HUNDRED_MILLISECONDS).atMost(TWO_SECONDS)
                .until(() -> tokenManager.getCurrentToken().getValue(), is("2"));
    }

    // T.4.1
    // Verify that token renewal timing can be configured correctly.
    @Test
    public void renewalTimingConfigTest() {
        float refreshRatio = 0.71F;
        int delayInMsToRetry = 201;
        int lowerRefreshBoundMillis = 301;
        int maxAttemptsToRetry = 6;
        int tokenRequestExecTimeoutInMs = 401;
        TokenAuthConfig tokenAuthConfig = EntraIDTokenAuthConfigBuilder.builder()
                .expirationRefreshRatio(refreshRatio).delayInMsToRetry(delayInMsToRetry)
                .lowerRefreshBoundMillis(lowerRefreshBoundMillis)
                .maxAttemptsToRetry(maxAttemptsToRetry)
                .tokenRequestExecTimeoutInMs(tokenRequestExecTimeoutInMs).build();
        TokenManagerConfig config = tokenAuthConfig.getTokenManagerConfig();
        assertEquals(refreshRatio, config.getExpirationRefreshRatio(), 0.00000001F);
        assertEquals(delayInMsToRetry, config.getRetryPolicy().getdelayInMs());
        assertEquals(lowerRefreshBoundMillis, config.getLowerRefreshBoundMillis());
        assertEquals(maxAttemptsToRetry, config.getRetryPolicy().getMaxAttempts());
        assertEquals(tokenRequestExecTimeoutInMs, config.getTokenRequestExecTimeoutInMs());
    }

    // T.4.2
    // Verify that Azure AD-specific parameters can be configured correctly.
    @Test
    public void withKeyCert_azureADConfigTest() {
        PrivateKey key = mock(PrivateKey.class);
        X509Certificate cert = mock(X509Certificate.class);
        Set<String> scopes = Collections.singleton("testScope");
        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
            EntraIDIdentityProvider.class, (mock, context) -> {
                ServicePrincipalInfo info = (ServicePrincipalInfo) (context.arguments().get(0));
                assertEquals("testClientId", info.getClientId());
                assertEquals("testAuthority", info.getAuthority());
                assertEquals(key, info.getKey());
                assertEquals(cert, info.getCert());
                assertEquals(scopes, context.arguments().get(1));
            })) {
            TokenAuthConfig config = EntraIDTokenAuthConfigBuilder.builder()
                    .clientId("testClientId").authority("testAuthority").key(key, cert)
                    .scopes(scopes).build();
            config.getIdentityProviderConfig().getProvider();
        }
    }

    // T.4.2
    // Verify that Azure AD-specific parameters can be configured correctly.
    @Test
    public void withUserAssignedManagedId_azureADConfigTest() {
        Set<String> scopes = Collections.singleton("testScope");
        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
            EntraIDIdentityProvider.class, (mock, context) -> {
                ManagedIdentityInfo info = (ManagedIdentityInfo) (context.arguments().get(0));
                assertEquals("CLIENT_ID", ((Object) info.getId().getIdType()).toString());
                assertEquals("testUserManagedId", info.getId().getUserAssignedId());
                assertEquals(scopes, context.arguments().get(1));
            })) {
            TokenAuthConfig config = EntraIDTokenAuthConfigBuilder.builder()
                    .clientId("testClientId").authority("testAuthority")
                    .userAssignedManagedIdentity(UserManagedIdentityType.CLIENT_ID,
                        "testUserManagedId")
                    .scopes(scopes).build();
            config.getIdentityProviderConfig().getProvider();
        }
    }

    // T.4.2
    // Test configuration of custom identity provider parameters.
    @Test
    public void customProviderConfigTest() {
        IClientSecret secret = ClientCredentialFactory.createFromSecret(testCtx.getClientSecret());
        // Choose and configure any type of app with any parameters as needed
        ConfidentialClientApplication app = ConfidentialClientApplication
                .builder(testCtx.getClientId(), secret).build();
        // Customize credential parameters as needed
        ClientCredentialParameters parameters = ClientCredentialParameters
                .builder(Collections.singleton("testScope")).build();
        Supplier<IAuthenticationResult> supplier = () -> {
            try {
                return app.acquireToken(parameters).get();
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException(e);
            }
        };

        try (MockedConstruction<EntraIDIdentityProvider> mockedConstructor = mockConstruction(
            EntraIDIdentityProvider.class, (mock, context) -> {
                assertEquals(supplier, context.arguments().get(0));
            })) {
            TokenAuthConfig tokenAuthConfig = EntraIDTokenAuthConfigBuilder.builder()
                    .customEntraIdAuthenticationSupplier(supplier).build();
            tokenAuthConfig.getIdentityProviderConfig().getProvider();
        }
    }

    private void delay(long durationInMs) {
        try {
            Thread.sleep(durationInMs);
        } catch (InterruptedException e) {
        }
    }
}
