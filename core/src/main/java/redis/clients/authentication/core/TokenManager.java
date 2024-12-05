package redis.clients.authentication.core;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenManager {

    private TokenManagerConfig tokenManagerConfig;
    private IdentityProvider identityProvider;
    private TokenListener listener;
    private ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private ExecutorService executor = Executors.newFixedThreadPool(2);
    private boolean stopped = false;
    private ScheduledFuture<?> scheduledTask;
    private AtomicInteger numberOfRetries = new AtomicInteger(0);
    private Exception lastException;
    private Logger logger = LoggerFactory.getLogger(getClass());
    private Token currentToken = null;
    private AtomicBoolean started = new AtomicBoolean(false);

    public TokenManager(IdentityProvider identityProvider, TokenManagerConfig tokenManagerConfig) {
        this.identityProvider = identityProvider;
        this.tokenManagerConfig = tokenManagerConfig;
    }

    public void start(TokenListener listener, boolean blockForInitialToken) {

        if (!started.compareAndSet(false, true)) {
            throw new AuthXException("Token manager already started!");
        }
        this.listener = listener;
        ScheduledFuture<?> currentTask = scheduleNext(0);
        scheduledTask = currentTask;
        if (blockForInitialToken) {
            try {
                while (currentTask.get() == null) {
                    currentTask = scheduledTask;
                }
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new TokenRequestException(unwrap(e), lastException);
            }
        }
    }

    public void stop() {
        stopped = true;
        scheduledTask.cancel(true);
        scheduler.shutdown();
        executor.shutdown();
    }

    public TokenManagerConfig getConfig() {
        return tokenManagerConfig;
    }

    private ScheduledFuture<?> scheduleNext(long delay) {
        // Schedule the task to run after the calculated delay
        return scheduler.schedule(() -> renewToken(), delay, TimeUnit.MILLISECONDS);
    }

    protected Token renewToken() {
        if (stopped) {
            return null;
        }
        Token newToken = null;
        try {
            Future<Token> requestResult = executor.submit(() -> requestToken());
            newToken = requestResult.get(tokenManagerConfig.getTokenRequestExecTimeoutInMs(),
                TimeUnit.MILLISECONDS);
            currentToken = newToken;
            long delay = calculateRenewalDelay(newToken.getExpiresAt(), newToken.getReceivedAt());
            scheduledTask = scheduleNext(delay);
            listener.onTokenRenewed(newToken);
            return newToken;
        } catch (Exception e) {
            if (numberOfRetries.getAndIncrement() < tokenManagerConfig.getRetryPolicy()
                    .getMaxAttempts()) {
                scheduledTask = scheduleNext(tokenManagerConfig.getRetryPolicy().getdelayInMs());
            } else {
                TokenRequestException tre = new TokenRequestException(unwrap(e), lastException);
                listener.onError(tre);
                throw tre;
            }
        }
        return null;
    }

    protected Token requestToken() {
        lastException = null;
        try {
            return identityProvider.requestToken();
        } catch (Exception e) {
            lastException = e;
            logger.error("Request to identity provider failed with message: " + e.getMessage(), e);
            throw e;
        }
    }

    private Throwable unwrap(Exception e) {
        return (e instanceof ExecutionException) ? e.getCause() : e;
    }

    public Token getCurrentToken() {
        return currentToken;
    }

    public long calculateRenewalDelay(long expireDate, long issueDate) {
        long ttlLowerRefresh = ttlForLowerRefresh(expireDate);
        long ttlRatioRefresh = ttlForRatioRefresh(expireDate, issueDate);
        long delay = Math.min(ttlLowerRefresh, ttlRatioRefresh);

        return delay < 0 ? 0 : delay;
    }

    public long ttlForLowerRefresh(long expireDate) {
        return expireDate - tokenManagerConfig.getLowerRefreshBoundMillis()
                - System.currentTimeMillis();
    }

    protected long ttlForRatioRefresh(long expireDate, long issueDate) {
        long validDuration = expireDate - issueDate;
        long refreshBefore = validDuration
                - (long) (validDuration * tokenManagerConfig.getExpirationRefreshRatio());
        return expireDate - refreshBefore - System.currentTimeMillis();
    }
}
