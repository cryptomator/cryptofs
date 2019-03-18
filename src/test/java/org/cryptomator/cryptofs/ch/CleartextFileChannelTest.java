package org.cryptomator.cryptofs.ch;

import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.fh.ChunkCache;
import org.cryptomator.cryptofs.fh.ChunkData;
import org.cryptomator.cryptofs.fh.ExceptionsDuringWrite;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Supplier;

import static org.hamcrest.CoreMatchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CleartextFileChannelTest {

	private ChunkCache chunkCache = mock(ChunkCache.class);
	private ReadWriteLock readWriteLock = mock(ReadWriteLock.class);
	private Lock readLock = mock(Lock.class);
	private Lock writeLock = mock(Lock.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private FileContentCryptor fileContentCryptor = mock(FileContentCryptor.class);
	private FileChannel ciphertextFileChannel = mock(FileChannel.class);
	private EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
	private AtomicLong fileSize = new AtomicLong(100);
	private AtomicReference<Instant> lastModified = new AtomicReference(Instant.ofEpochMilli(0));
	private Supplier<BasicFileAttributeView> attributeViewSupplier = mock(Supplier.class);
	private BasicFileAttributeView attributeView = mock(BasicFileAttributeView.class);
	private ExceptionsDuringWrite exceptionsDuringWrite = mock(ExceptionsDuringWrite.class);
	private ChannelCloseListener closeListener = mock(ChannelCloseListener.class);

	private CleartextFileChannel inTest;

	@BeforeEach
	public void setUp() throws IOException {
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		when(chunkCache.get(Mockito.anyLong())).then(invocation -> ChunkData.wrap(ByteBuffer.allocate(100)));
		when(fileHeaderCryptor.headerSize()).thenReturn(50);
		when(fileContentCryptor.cleartextChunkSize()).thenReturn(100);
		when(fileContentCryptor.ciphertextChunkSize()).thenReturn(110);
		when(ciphertextFileChannel.size()).thenReturn(160l); // initial cleartext size will be 100
		when(attributeViewSupplier.get()).thenReturn(attributeView);
		when(readWriteLock.readLock()).thenReturn(readLock);
		when(readWriteLock.writeLock()).thenReturn(writeLock);

		inTest = new CleartextFileChannel(ciphertextFileChannel, readWriteLock, cryptor, chunkCache, options, fileSize, lastModified, attributeViewSupplier, exceptionsDuringWrite, closeListener);
	}

	@Test
	public void testSize() throws IOException {
		Assertions.assertEquals(100, inTest.size());
	}

	@Nested
	public class Position {

		@Test
		public void testInitialPositionIsZero() throws IOException {
			MatcherAssert.assertThat(inTest.position(), is(0L));
		}

		@Test
		public void testPositionCanBeSet() throws IOException {
			inTest.position(3727L);

			MatcherAssert.assertThat(inTest.position(), is(3727L));
		}

		@Test
		public void testPositionCanNotBeSetToANegativeValue() throws IOException {
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				inTest.position(-42);
			});
		}

	}

	@Nested
	public class Truncate {

		@Test
		public void testTruncateFailsWithIOExceptionIfNotWritable() throws IOException {
			when(options.writable()).thenReturn(false);

			Assertions.assertThrows(NonWritableChannelException.class, () -> {
				inTest.truncate(3727L);
			});
		}

		@Test
		public void testTruncateKeepsPositionIfNewSizeGreaterCurrentPosition() throws IOException {
			long newSize = 442;
			long currentPosition = 342;
			inTest.position(currentPosition);
			when(options.writable()).thenReturn(true);

			inTest.truncate(newSize);


			MatcherAssert.assertThat(inTest.position(), is(currentPosition));
		}

		@Test
		public void testTruncateSetsPositionToNewSizeIfSmallerCurrentPosition() throws IOException {
			inTest.position(90);
			when(options.writable()).thenReturn(true);

			inTest.truncate(50);

			Assertions.assertEquals(50, inTest.position());
		}

	}

	@Nested
	public class Force {

		@Test
		public void testForceDelegatesToOpenCryptoFileWithTrue() throws IOException {
			inTest.force(true);

			verify(ciphertextFileChannel).force(true);
		}

		@Test
		public void testForceDelegatesToOpenCryptoFileWithFalse() throws IOException {
			inTest.force(false);

			verify(ciphertextFileChannel).force(false);
		}

		@Test
		public void testForceInvalidatesChunkCacheWhenWritable() throws IOException {
			when(options.writable()).thenReturn(true);

			inTest.force(false);

			verify(chunkCache).invalidateAll();
		}

		@Test
		public void testForceRethrowsExceptionsDuringWrite() throws IOException {
			when(options.writable()).thenReturn(true);
			doThrow(new IOException("exception during write")).when(exceptionsDuringWrite).throwIfPresent();

			IOException e = Assertions.assertThrows(IOException.class, () -> {
				inTest.force(false);
			});
			Assertions.assertEquals("exception during write", e.getMessage());

			verify(chunkCache).invalidateAll();
		}

		@Test
		public void testForceUpdatesLastModifiedTime() throws IOException {
			when(options.writable()).thenReturn(true);
			lastModified.set(Instant.ofEpochMilli(123456789000l));
			FileTime fileTime = FileTime.from(lastModified.get());

			inTest.force(false);

			verify(attributeView).setTimes(fileTime, null, null);
		}

	}

	@Nested
	public class Close {

		@Test
		public void testCloseTriggersCloseListener() throws IOException {
			inTest.implCloseChannel();

			verify(closeListener).closed(inTest);
		}
	}

	@Test
	public void testMapThrowsUnsupportedOperationException() throws IOException {
		Assertions.assertThrows(UnsupportedOperationException.class, () -> {
			inTest.map(MapMode.PRIVATE, 3727L, 3727L);
		});
	}

//	public class Lock {
//
//		@Test
//		public void testTryLockReturnsNullIfDelegateReturnsNull() throws IOException {
//			boolean shared = true;
//			long position = 372L;
//			long size = 3828L;
//			when(openCryptoFile.tryLock(position, size, shared)).thenReturn(null);
//
//			FileLock result = inTest.tryLock(position, size, shared);
//
//			assertThat(result, is(nullValue()));
//		}
//
//		@Test
//		public void testTryLockReturnsCryptoFileLockWrappingDelegate() throws IOException {
//			boolean shared = true;
//			long position = 372L;
//			long size = 3828L;
//			FileLock delegate = mock(FileLock.class);
//			when(openCryptoFile.tryLock(position, size, shared)).thenReturn(delegate);
//
//			FileLock result = inTest.tryLock(position, size, shared);
//
//			assertThat(result, is(instanceOf(CryptoFileLock.class)));
//			CryptoFileLock cryptoFileLock = (CryptoFileLock) result;
//			assertThat(cryptoFileLock.acquiredBy(), is(inTest));
//			assertThat(cryptoFileLock.delegate(), is(delegate));
//			assertThat(cryptoFileLock.isShared(), is(shared));
//			assertThat(cryptoFileLock.position(), is(position));
//			assertThat(cryptoFileLock.size(), is(size));
//		}
//
//		@Test
//		public void tesLockReturnsCryptoFileLockWrappingDelegate() throws IOException {
//			boolean shared = true;
//			long position = 372L;
//			long size = 3828L;
//			FileLock delegate = mock(FileLock.class);
//			when(openCryptoFile.lock(position, size, shared)).thenReturn(delegate);
//
//			FileLock result = inTest.lock(position, size, shared);
//
//			assertThat(result, is(instanceOf(CryptoFileLock.class)));
//			CryptoFileLock cryptoFileLock = (CryptoFileLock) result;
//			assertThat(cryptoFileLock.acquiredBy(), is(inTest));
//			assertThat(cryptoFileLock.delegate(), is(delegate));
//			assertThat(cryptoFileLock.isShared(), is(shared));
//			assertThat(cryptoFileLock.position(), is(position));
//			assertThat(cryptoFileLock.size(), is(size));
//		}
//
//	}

	@Nested
	public class Read {

		@Test
		public void testReadFailsIfNotReadable() throws IOException {
			when(options.readable()).thenReturn(false);

			Assertions.assertThrows(NonReadableChannelException.class, () -> {
				inTest.read(ByteBuffer.allocate(10));
			});
		}

		@Test
		public void testReadFromMultipleChunks() throws IOException {
			when(ciphertextFileChannel.size()).thenReturn(5_500_000_160l); // initial cleartext size will be 5_000_000_100l
			when(options.readable()).thenReturn(true);

			inTest = new CleartextFileChannel(ciphertextFileChannel, readWriteLock, cryptor, chunkCache, options, fileSize, lastModified, attributeViewSupplier, exceptionsDuringWrite, closeListener);
			ByteBuffer buf = ByteBuffer.allocate(10);

			// A read from frist chunk:
			buf.clear();
			inTest.read(buf, 0);

			// B read from second and third chunk:
			buf.clear();
			inTest.read(buf, 195);

			// C read from position > maxint
			buf.clear();
			inTest.read(buf, 5_000_000_000l);

			InOrder inOrder = Mockito.inOrder(chunkCache, chunkCache, chunkCache, chunkCache);
			inOrder.verify(chunkCache).get(0l); // A
			inOrder.verify(chunkCache).get(1l); // B
			inOrder.verify(chunkCache).get(2l); // B
			inOrder.verify(chunkCache).get(50_000_000l); // C
			inOrder.verifyNoMoreInteractions();
		}

		@Test
		public void testReadIncrementsPositionByAmountRead() throws IOException {
			ByteBuffer buffer = ByteBuffer.allocate(55);
			when(options.readable()).thenReturn(true);

			inTest.position(11);
			inTest.read(buffer);

			Assertions.assertEquals(66, inTest.position());
		}

		@Test
		public void testReadDoesNotChangePositionOnEof() throws IOException {
			ByteBuffer buffer = ByteBuffer.allocate(10);
			inTest.position(100);
			when(options.readable()).thenReturn(true);

			inTest.read(buffer);

			Assertions.assertEquals(100, inTest.position());
		}

	}

	@Nested
	public class Write {

		@Test
		public void testWriteToMultipleChunks() throws IOException {
			when(options.writable()).thenReturn(true);
			when(fileHeaderCryptor.encryptHeader(any())).thenReturn(ByteBuffer.allocate(10));

			// A change 10 bytes inside first chunk:
			ByteBuffer buf1 = ByteBuffer.allocate(10);
			inTest.write(buf1, 0);

			// B change complete second chunk:
			ByteBuffer buf2 = ByteBuffer.allocate(100);
			inTest.write(buf2, 100);

			// C change complete chunk at position > maxint:
			ByteBuffer buf3 = ByteBuffer.allocate(100);
			inTest.write(buf3, 5000);

			InOrder inOrder = Mockito.inOrder(chunkCache, chunkCache, chunkCache);
			inOrder.verify(chunkCache).get(0l); // A
			inOrder.verify(chunkCache).set(Mockito.eq(1l), Mockito.any()); // B
			inOrder.verify(chunkCache).set(Mockito.eq(50l), Mockito.any()); // C
			inOrder.verifyNoMoreInteractions();
		}

		@Test
		public void testWriteFailsIfNotWritable() throws IOException {
			when(options.writable()).thenReturn(false);

			Assertions.assertThrows(NonWritableChannelException.class, () -> {
				inTest.write(ByteBuffer.allocate(10));
			});
		}

		@Test
		public void testWriteIncrementsPositionByAmountWritten() throws IOException {
			ByteBuffer buffer = ByteBuffer.allocate(110);
			when(options.writable()).thenReturn(true);

			Assertions.assertEquals(100, inTest.size());

			int written = inTest.write(buffer, 95); // old EOF at 100

			Assertions.assertEquals(110, written);
			Assertions.assertEquals(205, inTest.size());

			verify(chunkCache).get(0l);
			verify(chunkCache).set(Mockito.eq(1l), Mockito.any());
			verify(chunkCache).get(2l);
		}

		@Test
		public void testWriteWithBuffersFailsIfNotWritable() throws IOException {
			when(options.writable()).thenReturn(false);

			Assertions.assertThrows(NonWritableChannelException.class, () -> {
				inTest.write(null, 0, 0);
			});
		}

		@Test
		public void testWriteWithBuffersStartsWritingFromOffsetAndWritesLengthBuffers() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(21), ByteBuffer.allocate(19), ByteBuffer.allocate(14)};
			when(options.writable()).thenReturn(true);

			inTest.position(70);

			long written = inTest.write(buffers, 1, 2);
			Assertions.assertEquals(40, written);
		}

	}

	@Nested
	public class OperationsOnClosedChannelThrowClosedChannelException {

		@BeforeEach
		public void setUp() throws IOException {
			inTest.close();
		}

		@Test
		public void testGetPosition() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.position();
			});
		}

		@Test
		public void testSetPosition() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.position(3727L);
			});
		}

		@Test
		public void testRead() {
			when(options.readable()).thenReturn(true);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.read(ByteBuffer.allocate(10));
			});
		}

		@Test
		public void testWrite() {
			when(options.writable()).thenReturn(true);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.write(ByteBuffer.allocate(10));
			});
		}

		@Test
		public void testReadWithPosition() {
			when(options.readable()).thenReturn(true);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.read(ByteBuffer.allocate(10), 3727L);
			});
		}

		@Test
		public void testWriteWithPosition() {
			when(options.writable()).thenReturn(true);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.write(ByteBuffer.allocate(10), 3727L);
			});
		}

		@Test
		public void testTransferFrom() throws IOException {
			when(options.readable()).thenReturn(true);
			ReadableByteChannel source = mock(ReadableByteChannel.class);
			when(source.read(any())).thenReturn(58);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.transferFrom(source, 3727L, 58);
			});
		}

		@Test
		public void testTransferTo() throws IOException {
			when(options.readable()).thenReturn(true);
			WritableByteChannel target = mock(WritableByteChannel.class);
			when(target.write(any())).thenReturn(58);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.transferTo(3727L, 58, target);
			});
		}

		@Test
		public void testSize() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.size();
			});
		}

		@Test
		public void testTruncate() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.truncate(3727L);
			});
		}

		@Test
		public void testForce() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.force(true);
			});
		}

		@Test
		public void testLock() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.lock(3727L, 3727L, true);
			});
		}

		@Test
		public void testTryLock() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.tryLock(3727L, 3727L, true);
			});
		}

	}

}
