/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.spi.AbstractInterruptibleChannel;
import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.spongycastle.util.Arrays;

import de.bechte.junit.runners.context.HierarchicalContextRunner;

@RunWith(HierarchicalContextRunner.class)
public class AbstractFileChannelTest {

	private AbstractFileChannel channel;

	@Before
	public void setup() throws ReflectiveOperationException {
		channel = Mockito.mock(AbstractFileChannel.class);
		Field channelOpenField = AbstractInterruptibleChannel.class.getDeclaredField("open");
		channelOpenField.setAccessible(true);
		channelOpenField.set(channel, true);
		Field channelCloseLockField = AbstractInterruptibleChannel.class.getDeclaredField("closeLock");
		channelCloseLockField.setAccessible(true);
		channelCloseLockField.set(channel, new Object());
	}

	@Test
	public void testPosition() throws IOException {
		Mockito.when(channel.position()).thenCallRealMethod();
		Mockito.when(channel.position(Mockito.anyLong())).thenCallRealMethod();
		Assert.assertEquals(0, channel.position());
		Assert.assertEquals(channel, channel.position(5));
		Assert.assertEquals(5, channel.position());
		Assert.assertEquals(channel, channel.position(2));
		Assert.assertEquals(2, channel.position());
	}

	public class ReadTest {

		private final byte[] contents = "hello world".getBytes(StandardCharsets.US_ASCII);

		@Before
		public void setup() throws IOException {
			Mockito.when(channel.read(Mockito.any(ByteBuffer.class))).thenCallRealMethod();
			Mockito.when(channel.read(Mockito.any(ByteBuffer[].class), Mockito.anyInt(), Mockito.anyInt())).thenCallRealMethod();
			Mockito.when(channel.transferTo(Mockito.anyLong(), Mockito.anyLong(), Mockito.any())).thenCallRealMethod();
			Mockito.when(channel.read(Mockito.any(), Mockito.anyLong())).thenAnswer(new Answer<Integer>() {

				@Override
				public Integer answer(InvocationOnMock invocation) throws Throwable {
					ByteBuffer buf = invocation.getArgumentAt(0, ByteBuffer.class);
					long pos = invocation.getArgumentAt(1, Long.class);
					if (pos >= contents.length) {
						return -1;
					} else {
						int len = (int) Math.min(contents.length - pos, buf.remaining());
						buf.put(contents, (int) pos, len);
						return len;
					}
				}
			});
		}

		@Test
		public void testReadToBuffer() throws IOException {
			ByteBuffer buf = ByteBuffer.allocate(6);
			int read = channel.read(buf);
			Assert.assertEquals(6, read);
			Assert.assertArrayEquals(Arrays.copyOfRange(contents, 0, 6), buf.array());

			buf.clear();
			read = channel.read(buf);
			Assert.assertEquals(5, read);
			Assert.assertArrayEquals(Arrays.copyOfRange(contents, 6, 11), Arrays.copyOf(buf.array(), 5));
		}

		@Test
		public void testReadToBuffers1() throws IOException {
			ByteBuffer buf1 = ByteBuffer.allocate(6);
			ByteBuffer buf2 = ByteBuffer.allocate(5);
			long read = channel.read(new ByteBuffer[] {buf1, buf2});
			Assert.assertEquals(11, read);
			Assert.assertArrayEquals(Arrays.copyOfRange(contents, 0, 6), buf1.array());
			Assert.assertArrayEquals(Arrays.copyOfRange(contents, 6, 11), buf2.array());
		}

		@Test
		public void testReadToBuffers2() throws IOException {
			ByteBuffer buf1 = ByteBuffer.allocate(6);
			ByteBuffer buf2 = ByteBuffer.allocate(5);
			ByteBuffer buf3 = ByteBuffer.allocate(5);
			long read = channel.read(new ByteBuffer[] {buf1, buf2, buf3});
			Assert.assertEquals(11, read);
			Assert.assertArrayEquals(Arrays.copyOfRange(contents, 0, 6), buf1.array());
			Assert.assertArrayEquals(Arrays.copyOfRange(contents, 6, 11), buf2.array());
			Assert.assertArrayEquals(new byte[buf3.capacity()], buf3.array());
		}

		@Test
		public void testReadToBuffers3() throws IOException {
			ByteBuffer buf1 = ByteBuffer.allocate(11);
			long read1 = channel.read(new ByteBuffer[] {buf1});
			Assert.assertEquals(11, read1);
			Assert.assertArrayEquals(Arrays.copyOfRange(contents, 0, 11), buf1.array());

			buf1.clear();
			long read2 = channel.read(new ByteBuffer[] {buf1});
			Assert.assertEquals(-1, read2);
		}

		@Test
		public void testTransferTo() throws IOException {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			long transferred1 = channel.transferTo(6, 5, Channels.newChannel(baos));
			Assert.assertEquals(5l, transferred1);
			Assert.assertArrayEquals(Arrays.copyOfRange(contents, 6, 11), baos.toByteArray());

			baos.reset();
			long transferred2 = channel.transferTo(0, 11, Channels.newChannel(baos));
			Assert.assertEquals(11l, transferred2);
			Assert.assertArrayEquals(contents, baos.toByteArray());

			baos.reset();
			long transferred3 = channel.transferTo(11, 3, Channels.newChannel(baos));
			Assert.assertEquals(0l, transferred3);
			Assert.assertArrayEquals(new byte[0], baos.toByteArray());
		}

	}

	public class WriteTest {

		private byte[] contents;

		@Before
		public void setup() throws IOException {
			contents = new byte[11];
			Mockito.when(channel.size()).thenReturn(11l);
			Mockito.when(channel.write(Mockito.any(ByteBuffer.class))).thenCallRealMethod();
			Mockito.when(channel.write(Mockito.any(ByteBuffer[].class), Mockito.anyInt(), Mockito.anyInt())).thenCallRealMethod();
			Mockito.when(channel.transferFrom(Mockito.any(), Mockito.anyLong(), Mockito.anyLong())).thenCallRealMethod();
			Mockito.when(channel.write(Mockito.any(), Mockito.anyLong())).thenAnswer(new Answer<Integer>() {

				@Override
				public Integer answer(InvocationOnMock invocation) throws Throwable {
					ByteBuffer buf = invocation.getArgumentAt(0, ByteBuffer.class);
					long pos = invocation.getArgumentAt(1, Long.class);
					int len = (int) Math.min(contents.length - pos, buf.remaining());
					buf.get(contents, (int) pos, len);
					return len;
				}
			});
		}

		@Test
		public void testWriteFromBuffer() throws IOException {
			ByteBuffer buf1 = ByteBuffer.wrap("hello ".getBytes(StandardCharsets.US_ASCII));
			int written1 = channel.write(buf1);
			Assert.assertEquals(6, written1);
			Assert.assertArrayEquals(buf1.array(), Arrays.copyOfRange(contents, 0, 6));

			ByteBuffer buf2 = ByteBuffer.wrap("world".getBytes(StandardCharsets.US_ASCII));
			int written2 = channel.write(buf2);
			Assert.assertEquals(5, written2);
			Assert.assertArrayEquals(buf2.array(), Arrays.copyOfRange(contents, 6, 11));
		}

		@Test
		public void testWriteFromBuffers1() throws IOException {
			ByteBuffer buf1 = ByteBuffer.wrap("hello ".getBytes(StandardCharsets.US_ASCII));
			ByteBuffer buf2 = ByteBuffer.wrap("world".getBytes(StandardCharsets.US_ASCII));
			long written = channel.write(new ByteBuffer[] {buf1, buf2});
			Assert.assertEquals(11, written);
			Assert.assertArrayEquals(buf1.array(), Arrays.copyOfRange(contents, 0, 6));
			Assert.assertArrayEquals(buf2.array(), Arrays.copyOfRange(contents, 6, 11));
		}

		@Test
		public void testWriteFromBuffers2() throws IOException {
			ByteBuffer buf1 = ByteBuffer.wrap("hello ".getBytes(StandardCharsets.US_ASCII));
			ByteBuffer buf2 = ByteBuffer.wrap("world".getBytes(StandardCharsets.US_ASCII));
			ByteBuffer buf3 = ByteBuffer.allocate(5);
			long written = channel.write(new ByteBuffer[] {buf1, buf2, buf3});
			Assert.assertEquals(11, written);
			Assert.assertArrayEquals(buf1.array(), Arrays.copyOfRange(contents, 0, 6));
			Assert.assertArrayEquals(buf2.array(), Arrays.copyOfRange(contents, 6, 11));
		}

		@Test
		public void testWriteFromBuffers3() throws IOException {
			ByteBuffer buf1 = ByteBuffer.wrap("hello world".getBytes(StandardCharsets.US_ASCII));
			long written1 = channel.write(new ByteBuffer[] {buf1});
			Assert.assertEquals(11, written1);
			Assert.assertArrayEquals(buf1.array(), Arrays.copyOfRange(contents, 0, 11));

			buf1.clear();
			long written2 = channel.write(new ByteBuffer[] {buf1});
			Assert.assertEquals(0, written2);
		}

		@Test
		public void testTransferFrom() throws IOException {
			byte[] buf1 = "hello ".getBytes(StandardCharsets.US_ASCII);
			long transferred1 = channel.transferFrom(Channels.newChannel(new ByteArrayInputStream(buf1)), 0, 6);
			Assert.assertEquals(6l, transferred1);
			Assert.assertArrayEquals(buf1, Arrays.copyOfRange(contents, 0, 6));

			byte[] buf2 = "world ".getBytes(StandardCharsets.US_ASCII);
			long transferred2 = channel.transferFrom(Channels.newChannel(new ByteArrayInputStream(buf2)), 6, 11);
			Assert.assertEquals(5l, transferred2);
			Assert.assertArrayEquals("hello world".getBytes(StandardCharsets.US_ASCII), contents);

			long transferred3 = channel.transferFrom(Channels.newChannel(new ByteArrayInputStream(buf2)), 100, 11);
			Assert.assertEquals(0l, transferred3);
			Assert.assertArrayEquals("hello world".getBytes(StandardCharsets.US_ASCII), contents);
		}

	}

}
