package redis.clients.authentication.core;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenManager {

    private TokenManagerConfig tokenManagerConfig;
    private IdentityProvider identityProvider;
    private TokenListener listener;
    private ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private ExecutorService executor = Executors.newSingleThreadExecutor();
    private boolean stopped = false;
    private ScheduledFuture<?> scheduledTask;
    private int numberOfRetries = 0;
    private Exception lastException;
    private Logger logger = LoggerFactory.getLogger(getClass());

    public TokenManager(IdentityProvider identityProvider, TokenManagerConfig tokenManagerConfig) {
        this.identityProvider = identityProvider;
        this.tokenManagerConfig = tokenManagerConfig;
    }

    public void start(TokenListener listener, boolean blockForInitialToken)
            throws InterruptedException, ExecutionException, TimeoutException {

        this.listener = listener;
        ScheduledFuture<?> currentTask = scheduleNext(0);
        scheduledTask = currentTask;
        if (blockForInitialToken) {
            while (currentTask.get() == null) {
                currentTask = scheduledTask;
            }
        }
    }

    public void stop() {
        stopped = true;
        scheduledTask.cancel(true);
        scheduler.shutdown();
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
            long delay = calculateRenewalDelay(newToken.getExpiresAt(), newToken.getReceivedAt());
            scheduledTask = scheduleNext(delay);
            listener.onTokenRenewed(newToken);
            return newToken;
        } catch (Exception e) {
            if (numberOfRetries < tokenManagerConfig.getRetryPolicy().getMaxAttempts()) {
                numberOfRetries++;
                scheduledTask = scheduleNext(tokenManagerConfig.getRetryPolicy().getdelayInMs());
            } else {
                TokenRequestException tre = new TokenRequestException(e, lastException);
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
