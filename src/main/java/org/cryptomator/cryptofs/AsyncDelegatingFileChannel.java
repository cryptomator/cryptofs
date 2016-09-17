/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.CompletionHandler;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

class AsyncDelegatingFileChannel extends AsynchronousFileChannel {

	private final FileChannel channel;
	private final ExecutorService executor;

	public AsyncDelegatingFileChannel(FileChannel channel, ExecutorService executor) {
		this.channel = channel;
		this.executor = executor;
	}

	/**
	 * @deprecated only for testing
	 */
	@Deprecated
	FileChannel getChannel() {
		return channel;
	}

	/**
	 * @deprecated only for testing
	 */
	@Deprecated
	ExecutorService getExecutor() {
		return executor;
	}

	@Override
	public void close() throws IOException {
		channel.close();
	}

	@Override
	public boolean isOpen() {
		return channel.isOpen();
	}

	@Override
	public long size() throws IOException {
		return channel.size();
	}

	@Override
	public AsynchronousFileChannel truncate(long size) throws IOException {
		channel.truncate(size);
		return this;
	}

	@Override
	public void force(boolean metaData) throws IOException {
		channel.force(metaData);
	}

	@Override
	public <A> void lock(long position, long size, boolean shared, A attachment, CompletionHandler<FileLock, ? super A> handler) {
		executor.submit(new CompletionHandlerInvoker<>(lock(position, size, shared), handler, attachment));
	}

	@Override
	public Future<FileLock> lock(long position, long size, boolean shared) {
		if (!isOpen()) {
			return exceptionalFuture(new ClosedChannelException());
		}
		return executor.submit(() -> {
			return channel.lock(position, size, shared);
		});
	}

	@Override
	public FileLock tryLock(long position, long size, boolean shared) throws IOException {
		return channel.tryLock(position, size, shared);
	}

	@Override
	public <A> void read(ByteBuffer dst, long position, A attachment, CompletionHandler<Integer, ? super A> handler) {
		executor.submit(new CompletionHandlerInvoker<>(read(dst, position), handler, attachment));
	}

	@Override
	public Future<Integer> read(ByteBuffer dst, long position) {
		if (!isOpen()) {
			return exceptionalFuture(new ClosedChannelException());
		}
		return executor.submit(() -> {
			return channel.read(dst, position);
		});
	}

	@Override
	public <A> void write(ByteBuffer src, long position, A attachment, CompletionHandler<Integer, ? super A> handler) {
		executor.submit(new CompletionHandlerInvoker<>(write(src, position), handler, attachment));
	}

	@Override
	public Future<Integer> write(ByteBuffer src, long position) {
		if (!isOpen()) {
			return exceptionalFuture(new ClosedChannelException());
		}
		return executor.submit(() -> {
			return channel.write(src, position);
		});
	}

	private <T> Future<T> exceptionalFuture(Throwable exception) {
		CompletableFuture<T> future = new CompletableFuture<>();
		future.completeExceptionally(exception);
		return future;
	}

	/**
	 * Gets the result from the given future and invokes the completion handler upon success or failure.
	 */
	private static class CompletionHandlerInvoker<T, A> implements Runnable {

		private final Future<T> future;
		private final CompletionHandler<T, ? super A> completionHandler;
		private final A attachment;

		public CompletionHandlerInvoker(Future<T> future, CompletionHandler<T, ? super A> completionHandler, A attachment) {
			this.future = Objects.requireNonNull(future);
			this.completionHandler = Objects.requireNonNull(completionHandler);
			this.attachment = attachment;
		}

		@Override
		public void run() {
			try {
				T result = future.get();
				completionHandler.completed(result, attachment);
			} catch (ExecutionException e) {
				completionHandler.failed(e.getCause(), attachment);
			} catch (CancellationException | InterruptedException e) {
				completionHandler.failed(e, attachment);
			}
		}

	}

}
