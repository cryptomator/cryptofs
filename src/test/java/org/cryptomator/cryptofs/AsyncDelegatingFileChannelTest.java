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
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.CompletionHandler;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.spi.AbstractInterruptibleChannel;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import de.bechte.junit.runners.context.HierarchicalContextRunner;

@RunWith(HierarchicalContextRunner.class)
public class AsyncDelegatingFileChannelTest {

	private final ExecutorService executor = Executors.newSingleThreadExecutor();

	private FileChannel channel;
	private AsyncDelegatingFileChannel asyncChannel;

	@Before
	public void setup() throws ReflectiveOperationException {
		channel = Mockito.mock(FileChannel.class);
		Field channelOpenField = AbstractInterruptibleChannel.class.getDeclaredField("open");
		channelOpenField.setAccessible(true);
		channelOpenField.set(channel, true);
		Field channelCloseLockField = AbstractInterruptibleChannel.class.getDeclaredField("closeLock");
		channelCloseLockField.setAccessible(true);
		channelCloseLockField.set(channel, new Object());
		asyncChannel = new AsyncDelegatingFileChannel(channel, executor);
	}

	@Test
	public void testIsOpen() throws IOException {
		Assert.assertTrue(asyncChannel.isOpen());
		channel.close();
		Assert.assertFalse(asyncChannel.isOpen());
	}

	@Test
	public void testClose() throws IOException {
		Assert.assertTrue(asyncChannel.isOpen());
		asyncChannel.close();
		Assert.assertFalse(asyncChannel.isOpen());
	}

	@Test
	public void testSize() throws IOException {
		Mockito.when(channel.size()).thenReturn(123l);
		Assert.assertEquals(123l, asyncChannel.size());
		Mockito.verify(channel).size();
	}

	@Test
	public void testTruncate() throws IOException {
		Assert.assertEquals(asyncChannel, asyncChannel.truncate(123l));
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
		Assert.assertNull(asyncChannel.tryLock(0l, 42l, true));
		FileLock lock = Mockito.mock(FileLock.class);
		Mockito.when(channel.tryLock(Mockito.anyLong(), Mockito.anyLong(), Mockito.anyBoolean())).thenReturn(lock);
		Assert.assertEquals(lock, asyncChannel.tryLock(0l, 42l, true));
	}

	public class LockTest {

		@Test
		public void testSuccess() throws IOException, InterruptedException, ExecutionException {
			final FileLock lock = Mockito.mock(FileLock.class);
			Mockito.when(channel.lock(Mockito.anyLong(), Mockito.anyLong(), Mockito.anyBoolean())).thenAnswer(new Answer<FileLock>() {
				@Override
				public FileLock answer(InvocationOnMock invocation) throws Throwable {
					Thread.sleep(100);
					return lock;
				}
			});

			CountDownLatch cdl = new CountDownLatch(1);
			AtomicReference<FileLock> result = new AtomicReference<>();
			AtomicReference<String> attachment = new AtomicReference<>();
			AtomicReference<Throwable> exception = new AtomicReference<>();
			asyncChannel.lock(123l, 234l, true, "bam", new CompletionHandler<FileLock, String>() {

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
			Assert.assertEquals("bam", attachment.get());
			Assert.assertEquals(lock, result.get());
			Assert.assertNull(exception.get());
		}

		@Test(expected = ClosedChannelException.class)
		public void testClosed() throws Throwable {
			channel.close();
			try {
				asyncChannel.lock().get();
				Assert.fail();
			} catch (InterruptedException | ExecutionException e) {
				throw e.getCause();
			}
		}

		@Test
		public void testExecutionException() throws Throwable {
			Mockito.when(channel.lock(Mockito.anyLong(), Mockito.anyLong(), Mockito.anyBoolean())).thenAnswer(new Answer<FileLock>() {
				@Override
				public FileLock answer(InvocationOnMock invocation) throws Throwable {
					throw new java.lang.ArithmeticException("fail");
				}
			});

			CountDownLatch cdl = new CountDownLatch(1);
			AtomicReference<FileLock> result = new AtomicReference<>();
			AtomicReference<String> attachment = new AtomicReference<>();
			AtomicReference<Throwable> exception = new AtomicReference<>();
			asyncChannel.lock(123l, 234l, true, "bam", new CompletionHandler<FileLock, String>() {

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
			Assert.assertEquals("bam", attachment.get());
			Assert.assertNull(result.get());
			Assert.assertThat(exception.get(), CoreMatchers.instanceOf(ArithmeticException.class));
		}

	}

	public class ReadTest {

		@Test
		public void testSuccess() throws IOException, InterruptedException, ExecutionException {
			Mockito.when(channel.read(Mockito.any(), Mockito.anyLong())).thenAnswer(new Answer<Integer>() {
				@Override
				public Integer answer(InvocationOnMock invocation) throws Throwable {
					ByteBuffer dst = invocation.getArgument(0);
					Thread.sleep(100);
					int read = dst.remaining();
					dst.position(dst.position() + read);
					return read;
				}
			});

			CountDownLatch cdl = new CountDownLatch(1);
			AtomicReference<Integer> result = new AtomicReference<>();
			AtomicReference<String> attachment = new AtomicReference<>();
			AtomicReference<Throwable> exception = new AtomicReference<>();
			ByteBuffer buf = ByteBuffer.allocate(42);
			asyncChannel.read(buf, 0l, "bam", new CompletionHandler<Integer, String>() {

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
			Assert.assertEquals("bam", attachment.get());
			Assert.assertEquals(Integer.valueOf(42), result.get());
			Assert.assertNull(exception.get());
		}

		@Test(expected = ClosedChannelException.class)
		public void testClosed() throws Throwable {
			channel.close();
			try {
				asyncChannel.read(ByteBuffer.allocate(0), 0l).get();
				Assert.fail();
			} catch (InterruptedException | ExecutionException e) {
				throw e.getCause();
			}
		}

	}

	public class WriteTest {

		@Test
		public void testSuccess() throws IOException, InterruptedException, ExecutionException {
			Mockito.when(channel.write(Mockito.any(), Mockito.anyLong())).thenAnswer(new Answer<Integer>() {
				@Override
				public Integer answer(InvocationOnMock invocation) throws Throwable {
					ByteBuffer dst = invocation.getArgument(0);
					Thread.sleep(100);
					int read = dst.remaining();
					dst.position(dst.position() + read);
					return read;
				}
			});

			CountDownLatch cdl = new CountDownLatch(1);
			AtomicReference<Integer> result = new AtomicReference<>();
			AtomicReference<String> attachment = new AtomicReference<>();
			AtomicReference<Throwable> exception = new AtomicReference<>();
			ByteBuffer buf = ByteBuffer.allocate(42);
			asyncChannel.write(buf, 0l, "bam", new CompletionHandler<Integer, String>() {

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
			Assert.assertEquals("bam", attachment.get());
			Assert.assertEquals(Integer.valueOf(42), result.get());
			Assert.assertNull(exception.get());
		}

		@Test(expected = ClosedChannelException.class)
		public void testClosed() throws Throwable {
			channel.close();
			try {
				asyncChannel.write(ByteBuffer.allocate(0), 0l).get();
				Assert.fail();
			} catch (InterruptedException | ExecutionException e) {
				throw e.getCause();
			}
		}

	}

}
