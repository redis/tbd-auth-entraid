package redis.clients.authentication;

import static org.mockito.Mockito.when;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.either;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import redis.clients.authentication.core.IdentityProvider;
import redis.clients.authentication.core.SimpleToken;
import redis.clients.authentication.core.Token;
import redis.clients.authentication.core.TokenListener;
import redis.clients.authentication.core.TokenManager;
import redis.clients.authentication.core.TokenManagerConfig;
import redis.clients.authentication.core.TokenRequestException;

import static org.awaitility.Awaitility.await;
import java.util.concurrent.TimeUnit;

public class CoreAuthenticationUnitTests {

  public static class TokenManagerConfigWrapper extends TokenManagerConfig {
    int lower;
    float ratio;

    public TokenManagerConfigWrapper() {
      super(0, 0, 0, null);
    }

    @Override
    public int getLowerRefreshBoundMillis() {
      return lower;
    }

    @Override
    public float getExpirationRefreshRatio() {
      return ratio;
    }
  }

  @Test
  public void testCalculateRenewalDelay() {
    long delay = 0;
    long duration = 0;
    long issueDate;
    long expireDate;

    TokenManagerConfigWrapper config = new TokenManagerConfigWrapper();
    TokenManager manager = new TokenManager(() -> null, config);

    duration = 5000;
    config.lower = 2000;
    config.ratio = 0.5F;
    issueDate = System.currentTimeMillis();
    expireDate = issueDate + duration;

    delay = manager.calculateRenewalDelay(expireDate, issueDate);

    assertThat(delay, Matchers
        .greaterThanOrEqualTo(Math.min(duration - config.lower, (long) (duration * config.ratio))));

    duration = 10000;
    config.lower = 8000;
    config.ratio = 0.2F;
    issueDate = System.currentTimeMillis();
    expireDate = issueDate + duration;

    delay = manager.calculateRenewalDelay(expireDate, issueDate);

    assertThat(delay, Matchers
        .greaterThanOrEqualTo(Math.min(duration - config.lower, (long) (duration * config.ratio))));

    duration = 10000;
    config.lower = 10000;
    config.ratio = 0.2F;
    issueDate = System.currentTimeMillis();
    expireDate = issueDate + duration;

    delay = manager.calculateRenewalDelay(expireDate, issueDate);

    assertEquals(0, delay);

    duration = 0;
    config.lower = 5000;
    config.ratio = 0.2F;
    issueDate = System.currentTimeMillis();
    expireDate = issueDate + duration;

    delay = manager.calculateRenewalDelay(expireDate, issueDate);

    assertEquals(0, delay);

    duration = 10000;
    config.lower = 1000;
    config.ratio = 0.00001F;
    issueDate = System.currentTimeMillis();
    expireDate = issueDate + duration;

    delay = manager.calculateRenewalDelay(expireDate, issueDate);

    assertEquals(0, delay);

    duration = 10000;
    config.lower = 1000;
    config.ratio = 0.0001F;
    issueDate = System.currentTimeMillis();
    expireDate = issueDate + duration;

    delay = manager.calculateRenewalDelay(expireDate, issueDate);

    assertThat(delay, either(is(0L)).or(is(1L)));
  }

  @Test
  public void testTokenManagerStart()
      throws InterruptedException, ExecutionException, TimeoutException {

    IdentityProvider identityProvider = () -> new SimpleToken("tokenVal",
        System.currentTimeMillis() + 5 * 1000, System.currentTimeMillis(),
        Collections.singletonMap("oid", "user1"));

    TokenManager tokenManager = new TokenManager(identityProvider,
        new TokenManagerConfig(0.7F, 200, 2000, null));

    TokenListener listener = mock(TokenListener.class);
    final Token[] tokenHolder = new Token[1];
    doAnswer(invocation -> {
      Object[] args = invocation.getArguments();
      tokenHolder[0] = (Token) args[0];
      return null;
    }).when(listener).onTokenRenewed(any());

    tokenManager.start(listener, true);
    assertEquals(tokenHolder[0].getValue(), "tokenVal");
  }

  @Test
  public void testBlockForInitialToken() {
    IdentityProvider identityProvider = () -> {
      throw new RuntimeException("Test exception from identity provider!");
    };

    TokenManager tokenManager = new TokenManager(identityProvider,
        new TokenManagerConfig(0.7F, 200, 2000, new TokenManagerConfig.RetryPolicy(5, 100)));

    TokenRequestException e = assertThrows(TokenRequestException.class,
      () -> tokenManager.start(mock(TokenListener.class), true));

    assertEquals("Test exception from identity provider!",
      e.getCause().getCause().getMessage());
  }

  @Test
  public void testNoBlockForInitialToken()
      throws InterruptedException, ExecutionException, TimeoutException {
    int numberOfRetries = 5;
    CountDownLatch requesLatch = new CountDownLatch(numberOfRetries);
    IdentityProvider identityProvider = () -> {
      requesLatch.countDown();
      throw new RuntimeException("Test exception from identity provider!");
    };

    TokenManager tokenManager = new TokenManager(identityProvider, new TokenManagerConfig(0.7F, 200,
        2000, new TokenManagerConfig.RetryPolicy(numberOfRetries - 1, 100)));

    TokenListener listener = mock(TokenListener.class);
    tokenManager.start(listener, false);

    requesLatch.await();
    verify(listener, atLeastOnce()).onError(any());
    verify(listener, never()).onTokenRenewed(any());
  }

  @Test
  public void testTokenManagerWithFailingTokenRequest()
      throws InterruptedException, ExecutionException, TimeoutException {
    int numberOfRetries = 5;
    CountDownLatch requesLatch = new CountDownLatch(numberOfRetries);

    IdentityProvider identityProvider = mock(IdentityProvider.class);
    when(identityProvider.requestToken()).thenAnswer(invocation -> {
      requesLatch.countDown();
      if (requesLatch.getCount() > 0) {
        throw new RuntimeException("Test exception from identity provider!");
      }
      return new SimpleToken("tokenValX", System.currentTimeMillis() + 50 * 1000,
          System.currentTimeMillis(), Collections.singletonMap("oid", "user1"));
    });

    ArgumentCaptor<Token> argument = ArgumentCaptor.forClass(Token.class);

    TokenManager tokenManager = new TokenManager(identityProvider, new TokenManagerConfig(0.7F, 200,
        2000, new TokenManagerConfig.RetryPolicy(numberOfRetries - 1, 100)));

    TokenListener listener = mock(TokenListener.class);
    tokenManager.start(listener, false);
    requesLatch.await();
    verify(identityProvider, times(numberOfRetries)).requestToken();
    verify(listener, never()).onError(any());
    verify(listener).onTokenRenewed(argument.capture());
    assertEquals("tokenValX", argument.getValue().getValue());
  }

  @Test
  public void testTokenManagerWithHangingTokenRequest()
      throws InterruptedException, ExecutionException, TimeoutException {
    int sleepDuration = 200;
    int executionTimeout = 100;
    int tokenLifetime = 50 * 1000;
    int numberOfRetries = 5;
    CountDownLatch requesLatch = new CountDownLatch(numberOfRetries);

    IdentityProvider identityProvider = () -> {
      requesLatch.countDown();
      if (requesLatch.getCount() > 0) {
        try {
          Thread.sleep(sleepDuration);
        } catch (InterruptedException e) {
        }
        return null;
      }
      return new SimpleToken("tokenValX", System.currentTimeMillis() + tokenLifetime,
          System.currentTimeMillis(), Collections.singletonMap("oid", "user1"));
    };

    TokenManager tokenManager = new TokenManager(identityProvider, new TokenManagerConfig(0.7F, 200,
        executionTimeout, new TokenManagerConfig.RetryPolicy(numberOfRetries, 100)));

    TokenListener listener = mock(TokenListener.class);
    tokenManager.start(listener, false);
    requesLatch.await();
    verify(listener, never()).onError(any());
    await().atMost(2, TimeUnit.SECONDS).untilAsserted(() -> {
      verify(listener, times(1)).onTokenRenewed(any());
    });
  }
}
