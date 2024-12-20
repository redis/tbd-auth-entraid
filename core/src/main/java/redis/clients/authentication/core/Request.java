/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.core;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

interface Request {

    public Token getResult() throws InterruptedException, ExecutionException, TimeoutException;
}
