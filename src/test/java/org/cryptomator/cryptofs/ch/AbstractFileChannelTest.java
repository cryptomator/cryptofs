package org.cryptomator.cryptofs.ch;

import com.google.common.io.ByteStreams;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileLock;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;

public class AbstractFileChannelTest {

	private ReadWriteLock readWriteLock = Mockito.mock(ReadWriteLock.class);
	private Lock readLock = Mockito.mock(Lock.class);
	private Lock writeLock = Mockito.mock(Lock.class);
	private AbstractFileChannel delegate = Mockito.mock(AbstractFileChannel.class);

	@BeforeEach
	public void setup() {
		Mockito.when(readWriteLock.readLock()).thenReturn(readLock);
		Mockito.when(readWriteLock.writeLock()).thenReturn(writeLock);
	}

	@Nested
	public class Read {

		AbstractFileChannel inTest;

		@BeforeEach
		public void setup() {
			inTest = new TestChannel(readWriteLock, true, false, delegate);
		}

		@Test
		public void readWithBuffersFailsIfChannelNotReadable() throws IOException {
			AbstractFileChannel nonReadableChannel = new TestChannel(readWriteLock, false, false, delegate);

			Assertions.assertThrows(NonReadableChannelException.class, () -> {
				nonReadableChannel.read(null, 0, 0);
			});
		}

		@Test
		public void readWithBuffersDoesReadNothingWhenLengthIsZero() throws IOException {
			ByteBuffer[] buffers = new ByteBuffer[10];

			long read = inTest.read(buffers, 3, 0);

			Assertions.assertEquals(0l, read);
			Mockito.verify(delegate, Mockito.never()).readLocked(Mockito.any(), Mockito.anyLong());
		}

		@Test
		public void readWithBuffersReturnsEofIfHitOnFirstRead() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(10), ByteBuffer.allocate(10)};
			Mockito.when(delegate.readLocked(Mockito.any(), Mockito.anyLong())).thenReturn(-1);

			long read = inTest.read(buffers, 0, 3);

			Assertions.assertEquals(-1l, read);
		}

		@Test
		public void readWithBuffersAbortsIfEofIsHitAfterFirstRead() throws IOException {
			ByteBuffer buf1 = ByteBuffer.allocate(10);
			ByteBuffer buf2 = ByteBuffer.allocate(10);
			ByteBuffer buf3 = ByteBuffer.allocate(10);
			ByteBuffer[] buffers = {buf1, buf2, buf3};
			Mockito.when(delegate.readLocked(Mockito.same(buf1), Mockito.anyLong())).thenReturn(8);
			Mockito.when(delegate.readLocked(Mockito.same(buf2), Mockito.anyLong())).thenReturn(-1);


			long read = inTest.read(buffers, 0, 3);

			Assertions.assertEquals(8l, read);
			Mockito.verify(delegate).readLocked(Mockito.same(buf1), Mockito.anyLong());
			Mockito.verify(delegate).readLocked(Mockito.same(buf2), Mockito.anyLong());
			Mockito.verify(delegate, Mockito.never()).readLocked(Mockito.same(buf3), Mockito.anyLong());
		}

		@Test
		public void readWithBuffersReadsWithoutHittingEof() throws IOException {
			ByteBuffer buf1 = ByteBuffer.allocate(10);
			ByteBuffer buf2 = ByteBuffer.allocate(10);
			ByteBuffer buf3 = ByteBuffer.allocate(10);
			ByteBuffer[] buffers = {buf1, buf2, buf3};
			Mockito.when(delegate.readLocked(Mockito.same(buf1), Mockito.anyLong())).thenReturn(10);
			Mockito.when(delegate.readLocked(Mockito.same(buf2), Mockito.anyLong())).thenReturn(10);
			Mockito.when(delegate.readLocked(Mockito.same(buf3), Mockito.anyLong())).thenReturn(8);

			long read = inTest.read(buffers, 0, 3);

			Assertions.assertEquals(28l, read);
			Mockito.verify(delegate).readLocked(Mockito.same(buf1), Mockito.anyLong());
			Mockito.verify(delegate).readLocked(Mockito.same(buf2), Mockito.anyLong());
			Mockito.verify(delegate).readLocked(Mockito.same(buf3), Mockito.anyLong());
		}

	}

	@Nested
	public class Write {

		AbstractFileChannel inTest;

		@BeforeEach
		public void setup() {
			inTest = new TestChannel(readWriteLock, false, true, delegate);
		}

		@Test
		public void writeWithBuffersFailsIfChannelNotWrtiable() throws IOException {
			AbstractFileChannel nonWritableChannel = new TestChannel(readWriteLock, false, false, delegate);

			Assertions.assertThrows(NonWritableChannelException.class, () -> {
				nonWritableChannel.write(null, 0, 0);
			});
		}

		@Test
		public void writeWithBuffersDoesReadNothingWhenLengthIsZero() throws IOException {
			ByteBuffer[] buffers = new ByteBuffer[10];

			long written = inTest.write(buffers, 3, 0);

			Assertions.assertEquals(0l, written);
			Mockito.verify(delegate, Mockito.never()).writeLocked(Mockito.any(), Mockito.anyLong());
		}

		@Test
		public void writeWithBuffersWritesAllContents() throws IOException {
			ByteBuffer buf1 = ByteBuffer.allocate(10);
			ByteBuffer buf2 = ByteBuffer.allocate(0);
			ByteBuffer buf3 = ByteBuffer.allocate(8);
			ByteBuffer[] buffers = {buf1, buf2, buf3};
			Mockito.when(delegate.writeLocked(Mockito.same(buf1), Mockito.anyLong())).thenReturn(10);
			Mockito.when(delegate.writeLocked(Mockito.same(buf2), Mockito.anyLong())).thenReturn(0);
			Mockito.when(delegate.writeLocked(Mockito.same(buf3), Mockito.anyLong())).thenReturn(8);

			Mockito.when(delegate.size()).thenReturn(100l);
			inTest.position(30);

			long written = inTest.write(buffers, 0, 3);

			Assertions.assertEquals(18l, written);
			Mockito.verify(delegate).writeLocked(buf1, 30);
			Mockito.verify(delegate).writeLocked(buf2, 40);
			Mockito.verify(delegate).writeLocked(buf3, 40);
		}

	}

	@Nested
	public class TransferTo {

		AbstractFileChannel inTest;

		@BeforeEach
		public void setup() {
			inTest = new TestChannel(readWriteLock, true, false, delegate);
		}

		@Test
		public void transferToFailsIfChannelNotReadable() throws IOException {
			AbstractFileChannel nonReadableChannel = new TestChannel(readWriteLock, false, false, delegate);

			Assertions.assertThrows(NonReadableChannelException.class, () -> {
				nonReadableChannel.transferTo(0L, 0L, null);
			});
		}

		@Test
		public void transferRequestedBytes() throws IOException {
			long fileSize = 50_000l;
			Mockito.when(inTest.readLocked(Mockito.any(), Mockito.anyLong())).thenAnswer(invocation -> {
				ByteBuffer buf = invocation.getArgument(0);
				long pos = invocation.getArgument(1);
				if (pos >= fileSize) {
					return -1;
				} else {
					int n = (int) Math.min(buf.remaining(), fileSize - pos);
					buf.position(buf.position() + n);
					return n;
				}
			});

			OutputStream out = ByteStreams.nullOutputStream();
			long transferred = inTest.transferTo(0, 42427, Channels.newChannel(out));

			Assertions.assertEquals(42427, transferred);
		}

		@Test
		public void transferRequestedBytesTillEof() throws IOException {
			long fileSize = 50_000l;
			Mockito.when(inTest.readLocked(Mockito.any(), Mockito.anyLong())).thenAnswer(invocation -> {
				ByteBuffer buf = invocation.getArgument(0);
				long pos = invocation.getArgument(1);
				if (pos >= fileSize) {
					return -1;
				} else {
					int n = (int) Math.min(buf.remaining(), fileSize - pos);
					buf.position(buf.position() + n);
					return n;
				}
			});

			OutputStream out = ByteStreams.nullOutputStream();
			long transferred = inTest.transferTo(30_000, 50_000, Channels.newChannel(out));

			Assertions.assertEquals(20_000, transferred);
		}

	}

	@Nested
	public class TransferFrom {

		AbstractFileChannel inTest;

		@BeforeEach
		public void setup() {
			inTest = new TestChannel(readWriteLock, false, true, delegate);
		}

		@Test
		public void testTransferFromFailsIfChannelNotWritable() throws IOException {
			AbstractFileChannel nonWritableChannel = new TestChannel(readWriteLock, false, false, delegate);

			Assertions.assertThrows(NonWritableChannelException.class, () -> {
				nonWritableChannel.transferFrom(null, 0L, 0L);
			});
		}

		@Test
		public void testTransferFromWritesAllBytesToFile() throws IOException {
			LongAdder written = new LongAdder();
			Mockito.when(inTest.writeLocked(Mockito.any(), Mockito.anyLong())).thenAnswer(invocation -> {
				ByteBuffer buf = invocation.getArgument(0);
				int n = buf.remaining();
				buf.position(buf.position() + n);
				written.add(n);
				return n;
			});

			ByteArrayInputStream in = new ByteArrayInputStream(new byte[60_000]);
			long transferred = inTest.transferFrom(Channels.newChannel(in), 0, 80_000);

			Assertions.assertEquals(60_000l, transferred);
			Assertions.assertEquals(60_000l, written.sum());
		}

		@Test
		public void testTransferFromWritesNumberOfSpecifiedBytesToFile() throws IOException {
			LongAdder written = new LongAdder();
			Mockito.when(inTest.writeLocked(Mockito.any(), Mockito.anyLong())).thenAnswer(invocation -> {
				ByteBuffer buf = invocation.getArgument(0);
				int n = buf.remaining();
				buf.position(buf.position() + n);
				written.add(n);
				return n;
			});

			ByteArrayInputStream in = new ByteArrayInputStream(new byte[60_000]);
			long transferred = inTest.transferFrom(Channels.newChannel(in), 0, 42_000);

			Assertions.assertEquals(42_000l, transferred);
			Assertions.assertEquals(42_000l, written.sum());
		}

	}


	private static class TestChannel extends AbstractFileChannel {

		private final boolean readable;
		private final boolean writable;
		private final AbstractFileChannel delegate;

		public TestChannel(ReadWriteLock readWriteLock, boolean readable, boolean writable, AbstractFileChannel delegate) {
			super(readWriteLock);
			this.readable = readable;
			this.writable = writable;
			this.delegate = delegate;
		}

		@Override
		public long size() throws IOException {
			return delegate.size();
		}

		@Override
		public void force(boolean metaData) throws IOException {
			delegate.force(metaData);
		}

		@Override
		public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
			return delegate.map(mode, position, size);
		}

		@Override
		public FileLock lock(long position, long size, boolean shared) throws IOException {
			return delegate.lock(position, size, shared);
		}

		@Override
		public FileLock tryLock(long position, long size, boolean shared) throws IOException {
			return delegate.tryLock(position, size, shared);
		}

		@Override
		protected boolean isWritable() {
			return writable;
		}

		@Override
		protected boolean isReadable() {
			return readable;
		}

		@Override
		protected int readLocked(ByteBuffer dst, long position) throws IOException {
			return delegate.readLocked(dst, position);
		}

		@Override
		protected int writeLocked(ByteBuffer src, long position) throws IOException {
			return delegate.writeLocked(src, position);
		}

		@Override
		protected void truncateLocked(long size) throws IOException {
			delegate.truncateLocked(size);
		}
	}

}
