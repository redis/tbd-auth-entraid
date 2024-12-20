/*
 * Copyright 2024, Redis Ltd. and Contributors All rights reserved. Licensed under the MIT License.
 */
package redis.clients.authentication.core;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Schedules a task for token renewal.
 */
class RenewalScheduler {
    private ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private RenewalTask lastTask;
    private Supplier<Token> renewToken;
    private boolean stopped = false;

    public RenewalScheduler(Supplier<Token> renewToken) {
        this.renewToken = renewToken;
    }

    /**
     * Schedules a task to renew the token with a given delay
     * Wraps the supplier function into RenewalTask
     * @param delay
     * @return
     */
    public RenewalTask scheduleNext(long delay) {
        // Schedule the task to run after the given delay
        lastTask = new RenewalTask(
                scheduler.schedule(() -> renewToken.get(), delay, TimeUnit.MILLISECONDS));
        return lastTask;
    }

    /**
     * Returns the last task that was scheduled
     * @return
     */
    public RenewalTask getLastTask() {
        return lastTask;
    }

    /**
     * Waits for given task to complete
     * If there is an execution error in the task, it throws the same exception
     * It keeps following if there are consecutive tasks until a non-null result is returned or an exception occurs
     * This makes the caller thread to wait until a first token is received with or after the pendingTask
     * @param pendingTask
     * @throws InterruptedException
     * @throws ExecutionException
     */
    public void waitFor(RenewalTask pendingTask) throws InterruptedException, ExecutionException {
        while (!stopped && pendingTask.waitForResultOrError() == null) {
            pendingTask = getLastTask();
        }
    }

    public void stop() {
        stopped = true;
        lastTask.cancel();
        scheduler.shutdown();
    }
}
