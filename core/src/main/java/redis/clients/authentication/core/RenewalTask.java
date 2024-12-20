/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.core;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledFuture;

class RenewalTask {

    private ScheduledFuture<Token> future;

    public RenewalTask(ScheduledFuture<Token> future) {
        this.future = future;
    }

    public Token waitForResultOrError() throws InterruptedException, ExecutionException {
        return future.get();
    }

    public void cancel() {
        future.cancel(true);
    }
}
