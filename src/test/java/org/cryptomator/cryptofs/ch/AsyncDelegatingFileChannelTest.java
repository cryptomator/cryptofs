/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.ch;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.CompletionHandler;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class AsyncDelegatingFileChannelTest {

	private final ExecutorService executor = Executors.newSingleThreadExecutor();

	private FileChannel channel;
	private AsyncDelegatingFileChannel asyncChannel;

	@BeforeEach
	public void setup() throws ReflectiveOperationException {
		channel = Mockito.mock(FileChannel.class);
		asyncChannel = new AsyncDelegatingFileChannel(channel, executor);
	}

	@Test
	public void testIsOpen() {
		Mockito.when(channel.isOpen()).thenReturn(true);
		Assertions.assertTrue(asyncChannel.isOpen());

		Mockito.when(channel.isOpen()).thenReturn(false);
		Assertions.assertFalse(asyncChannel.isOpen());
	}

	@Test
	public void testClose() throws IOException {
		asyncChannel.close();
		Mockito.verify(channel).close();
	}

	@Test
	public void testSize() throws IOException {
		Mockito.when(channel.size()).thenReturn(123l);
		Assertions.assertEquals(123l, asyncChannel.size());
		Mockito.verify(channel).size();
	}

	@Test
	public void testTruncate() throws IOException {
		Assertions.assertEquals(asyncChannel, asyncChannel.truncate(123l));
		Mockito.verify(channel).truncate(123l);
	}

	@Test
	public void testForce() throws IOException {
		asyncChannel.force(false);
		Mockito.verify(channel).force(false);
		asyncChannel.force(true);
		Mockito.verify(channel).force(true);
	}

	@Test
	public void testTryLock() throws IOException {
		Mockito.when(channel.tryLock(Mockito.anyLong(), Mockito.anyLong(), Mockito.anyBoolean())).thenReturn(null);
		Assertions.assertNull(asyncChannel.tryLock(0l, 42l, true));
		FileLock lock = Mockito.mock(FileLock.class);
		Mockito.when(channel.tryLock(Mockito.anyLong(), Mockito.anyLong(), Mockito.anyBoolean())).thenReturn(lock);
		Assertions.assertEquals(lock, asyncChannel.tryLock(0l, 42l, true));
	}

	@Nested
	public class LockTest {

		@Test
		public void testSuccess() throws IOException, InterruptedException {
			Mockito.when(channel.isOpen()).thenReturn(true);
			final FileLock lock = Mockito.mock(FileLock.class);
			Mockito.when(channel.lock(Mockito.anyLong(), Mockito.anyLong(), Mockito.anyBoolean())).thenAnswer(invocation -> {
				Thread.sleep(100);
				return lock;
			});

			CountDownLatch cdl = new CountDownLatch(1);
			AtomicReference<FileLock> result = new AtomicReference<>();
			AtomicReference<String> attachment = new AtomicReference<>();
			AtomicReference<Throwable> exception = new AtomicReference<>();
			asyncChannel.lock(123l, 234l, true, "bam", new CompletionHandler<>() {

				@Override
				public void completed(FileLock r, String a) {
					result.set(r);
					attachment.set(a);
					cdl.countDown();
				}

				@Override
				public void failed(Throwable e, String a) {
					exception.set(e);
					attachment.set(a);
					cdl.countDown();
				}
			});

			cdl.await(1000, TimeUnit.MILLISECONDS);

			Mockito.verify(channel).lock(123l, 234l, true);
			Assertions.assertEquals("bam", attachment.get());
			Assertions.assertEquals(lock, result.get());
			Assertions.assertNull(exception.get());
		}

		@Test
		public void testClosed() throws Throwable {
			channel.close();
			ExecutionException e = Assertions.assertThrows(ExecutionException.class, () -> {
				asyncChannel.lock().get();
			});
			Assertions.assertEquals(ClosedChannelException.class, e.getCause().getClass());
		}

		@Test
		public void testExecutionException() throws Throwable {
			Mockito.when(channel.isOpen()).thenReturn(true);
			Mockito.when(channel.lock(Mockito.anyLong(), Mockito.anyLong(), Mockito.anyBoolean())).thenAnswer(invocation -> {
				throw new ArithmeticException("fail");
			});

			CountDownLatch cdl = new CountDownLatch(1);
			AtomicReference<FileLock> result = new AtomicReference<>();
			AtomicReference<String> attachment = new AtomicReference<>();
			AtomicReference<Throwable> exception = new AtomicReference<>();
			asyncChannel.lock(123l, 234l, true, "bam", new CompletionHandler<>() {

				@Override
				public void completed(FileLock r, String a) {
					result.set(r);
					attachment.set(a);
					cdl.countDown();
				}

				@Override
				public void failed(Throwable e, String a) {
					exception.set(e);
					attachment.set(a);
					cdl.countDown();
				}
			});

			cdl.await(1000, TimeUnit.MILLISECONDS);

			Mockito.verify(channel).lock(123l, 234l, true);
			Assertions.assertEquals("bam", attachment.get());
			Assertions.assertNull(result.get());
			MatcherAssert.assertThat(exception.get(), CoreMatchers.instanceOf(ArithmeticException.class));
		}

	}

	@Nested
	public class ReadTest {

		@Test
		public void testSuccess() throws IOException, InterruptedException {
			Mockito.when(channel.isOpen()).thenReturn(true);
			Mockito.when(channel.read(Mockito.any(), Mockito.anyLong())).thenAnswer(invocation -> {
				ByteBuffer dst = invocation.getArgument(0);
				Thread.sleep(100);
				int read = dst.remaining();
				dst.position(dst.position() + read);
				return read;
			});

			CountDownLatch cdl = new CountDownLatch(1);
			AtomicReference<Integer> result = new AtomicReference<>();
			AtomicReference<String> attachment = new AtomicReference<>();
			AtomicReference<Throwable> exception = new AtomicReference<>();
			ByteBuffer buf = ByteBuffer.allocate(42);
			asyncChannel.read(buf, 0l, "bam", new CompletionHandler<>() {

				@Override
				public void completed(Integer r, String a) {
					result.set(r);
					attachment.set(a);
					cdl.countDown();
				}

				@Override
				public void failed(Throwable e, String a) {
					exception.set(e);
					attachment.set(a);
					cdl.countDown();
				}
			});

			cdl.await(1000, TimeUnit.MILLISECONDS);

			Mockito.verify(channel).read(buf, 0l);
			Assertions.assertEquals("bam", attachment.get());
			Assertions.assertEquals(Integer.valueOf(42), result.get());
			Assertions.assertNull(exception.get());
		}

		@Test
		public void testClosed() throws Throwable {
			channel.close();
			ExecutionException e = Assertions.assertThrows(ExecutionException.class, () -> {
				asyncChannel.read(ByteBuffer.allocate(0), 0l).get();
			});
			Assertions.assertEquals(ClosedChannelException.class, e.getCause().getClass());
		}

	}

	@Nested
	public class WriteTest {

		@Test
		public void testSuccess() throws IOException, InterruptedException {
			Mockito.when(channel.isOpen()).thenReturn(true);
			Mockito.when(channel.write(Mockito.any(), Mockito.anyLong())).thenAnswer(invocation -> {
				ByteBuffer dst = invocation.getArgument(0);
				Thread.sleep(100);
				int read = dst.remaining();
				dst.position(dst.position() + read);
				return read;
			});

			CountDownLatch cdl = new CountDownLatch(1);
			AtomicReference<Integer> result = new AtomicReference<>();
			AtomicReference<String> attachment = new AtomicReference<>();
			AtomicReference<Throwable> exception = new AtomicReference<>();
			ByteBuffer buf = ByteBuffer.allocate(42);
			asyncChannel.write(buf, 0l, "bam", new CompletionHandler<>() {

				@Override
				public void completed(Integer r, String a) {
					result.set(r);
					attachment.set(a);
					cdl.countDown();
				}

				@Override
				public void failed(Throwable e, String a) {
					exception.set(e);
					attachment.set(a);
					cdl.countDown();
				}
			});

			cdl.await(1000, TimeUnit.MILLISECONDS);

			Mockito.verify(channel).write(buf, 0l);
			Assertions.assertEquals("bam", attachment.get());
			Assertions.assertEquals(Integer.valueOf(42), result.get());
			Assertions.assertNull(exception.get());
		}

		@Test
		public void testClosed() throws Throwable {
			channel.close();
			ExecutionException e = Assertions.assertThrows(ExecutionException.class, () -> {
				asyncChannel.write(ByteBuffer.allocate(0), 0l).get();
			});
			Assertions.assertEquals(ClosedChannelException.class, e.getCause().getClass());
		}

	}

}
