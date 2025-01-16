package org.cryptomator.cryptofs.ch;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.fh.BufferPool;
import org.cryptomator.cryptofs.fh.Chunk;
import org.cryptomator.cryptofs.fh.ChunkCache;
import org.cryptomator.cryptofs.fh.ExceptionsDuringWrite;
import org.cryptomator.cryptofs.fh.FileHeaderHolder;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InOrder;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.channels.FileLock;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.spi.FileSystemProvider;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Consumer;

import static org.hamcrest.CoreMatchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CleartextFileChannelTest {

	private ChunkCache chunkCache = mock(ChunkCache.class);
	private BufferPool bufferPool = mock(BufferPool.class);
	private ReadWriteLock readWriteLock = mock(ReadWriteLock.class);
	private Lock readLock = mock(Lock.class);
	private Lock writeLock = mock(Lock.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private FileContentCryptor fileContentCryptor = mock(FileContentCryptor.class);
	private FileChannel ciphertextFileChannel = mock(FileChannel.class);
	private FileHeaderHolder headerHolder = mock(FileHeaderHolder.class);
	private AtomicBoolean headerIsPersisted = mock(AtomicBoolean.class);
	private EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
	private Path filePath = Mockito.mock(Path.class, "/foo/bar");
	private AtomicReference<Path> currentFilePath = new AtomicReference<>(filePath);
	private AtomicLong fileSize = new AtomicLong(100);
	private AtomicReference<Instant> lastModified = new AtomicReference<>(Instant.ofEpochMilli(0));
	private BasicFileAttributeView attributeView = mock(BasicFileAttributeView.class);
	private ExceptionsDuringWrite exceptionsDuringWrite = mock(ExceptionsDuringWrite.class);
	private Consumer<FileChannel> closeListener = mock(Consumer.class);
	private CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);

	private CleartextFileChannel inTest;

	@BeforeEach
	public void setUp() throws IOException {
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		when(chunkCache.getChunk(Mockito.anyLong())).then(invocation -> new Chunk(ByteBuffer.allocate(100), false, () -> {}));
		when(chunkCache.putChunk(Mockito.anyLong(), Mockito.any())).thenAnswer(invocation -> new Chunk(invocation.getArgument(1), true, () -> {}));
		when(bufferPool.getCleartextBuffer()).thenAnswer(invocation -> ByteBuffer.allocate(100));
		when(fileHeaderCryptor.headerSize()).thenReturn(50);
		when(headerHolder.headerIsPersisted()).thenReturn(headerIsPersisted);
		when(headerIsPersisted.getAndSet(anyBoolean())).thenReturn(true);
		when(fileContentCryptor.cleartextChunkSize()).thenReturn(100);
		when(fileContentCryptor.ciphertextChunkSize()).thenReturn(110);
		var fs = Mockito.mock(FileSystem.class);
		var fsProvider = Mockito.mock(FileSystemProvider.class);
		when(filePath.getFileSystem()).thenReturn(fs);
		when(fs.provider()).thenReturn(fsProvider);
		when(fsProvider.getFileAttributeView(filePath, BasicFileAttributeView.class)).thenReturn(attributeView);
		when(readWriteLock.readLock()).thenReturn(readLock);
		when(readWriteLock.writeLock()).thenReturn(writeLock);

		inTest = new CleartextFileChannel(ciphertextFileChannel, headerHolder, readWriteLock, cryptor, chunkCache, bufferPool, options, fileSize, lastModified, currentFilePath, exceptionsDuringWrite, closeListener, stats);
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

			verify(chunkCache).flush();
		}

		@Test
		public void testForceRethrowsExceptionsDuringWrite() throws IOException {
			when(options.writable()).thenReturn(true);
			doThrow(new IOException("exception during write")).when(exceptionsDuringWrite).throwIfPresent();

			IOException e = Assertions.assertThrows(IOException.class, () -> {
				inTest.force(false);
			});
			Assertions.assertEquals("exception during write", e.getMessage());

			verify(chunkCache).flush();
		}

		@Test
		public void testForceWithMetadataUpdatesLastModifiedTime() throws IOException {
			when(options.writable()).thenReturn(true);
			lastModified.set(Instant.ofEpochMilli(123456789000l));
			FileTime fileTime = FileTime.from(lastModified.get());

			inTest.force(true);

			verify(attributeView).setTimes(Mockito.eq(fileTime), Mockito.any(), Mockito.isNull());
		}

		@Test
		public void testForceWithoutMetadataDoesntUpdatesLastModifiedTime() throws IOException {
			when(options.writable()).thenReturn(true);
			lastModified.set(Instant.ofEpochMilli(123456789000l));

			inTest.force(false);

			verify(attributeView, Mockito.never()).setTimes(Mockito.any(), Mockito.any(), Mockito.any());
		}

	}

	@Nested
	public class Close {

		@Test
		@DisplayName("IOException during flush cleans up, persists lastModified and rethrows")
		public void testCloseIoExceptionFlush() throws IOException {
			var inSpy = Mockito.spy(inTest);
			Mockito.doThrow(IOException.class).when(inSpy).flush();

			Assertions.assertThrows(IOException.class, () -> inSpy.implCloseChannel());

			verify(closeListener).accept(ciphertextFileChannel);
			verify(ciphertextFileChannel).close();
			verify(inSpy).persistLastModified();
		}

		@Test
		@DisplayName("On close, first flush channel, then unregister")
		public void testCloseCipherChannelFlushBeforeUnregister() throws IOException {
			var inSpy = spy(inTest);
			inSpy.implCloseChannel();

			var ordering = inOrder(inSpy, closeListener);
			ordering.verify(inSpy).flush();
			verify(closeListener).accept(ciphertextFileChannel);
		}

		@Test
		@DisplayName("On close, first close channel, then persist lastModified")
		public void testCloseCipherChannelCloseBeforePersist() throws IOException {
			var inSpy = spy(inTest);
			inSpy.implCloseChannel();

			var ordering = inOrder(inSpy, ciphertextFileChannel);
			ordering.verify(ciphertextFileChannel).close();
			ordering.verify(inSpy).persistLastModified();
		}

		@Test
		public void testCloseUpdatesLastModifiedTimeIfWriteable() throws IOException {
			when(options.writable()).thenReturn(true);
			lastModified.set(Instant.ofEpochMilli(123456789000l));
			FileTime fileTime = FileTime.from(lastModified.get());

			inTest.implCloseChannel();

			verify(attributeView).setTimes(Mockito.eq(fileTime), Mockito.any(), Mockito.isNull());
		}

		@Test
		@DisplayName("IOException on persisting lastModified during close is ignored")
		public void testCloseExceptionOnLastModifiedPersistenceIgnored() throws IOException {
			when(options.writable()).thenReturn(true);
			lastModified.set(Instant.ofEpochMilli(123456789000l));

			var inSpy = Mockito.spy(inTest);
			Mockito.doThrow(IOException.class).when(inSpy).persistLastModified();

			Assertions.assertDoesNotThrow(inSpy::implCloseChannel);
			verify(closeListener).accept(ciphertextFileChannel);
			verify(ciphertextFileChannel).close();
		}

		@Test
		public void testCloseDoesNotUpdateLastModifiedTimeIfReadOnly() throws IOException {
			when(options.writable()).thenReturn(false);

			inTest.implCloseChannel();

			verify(attributeView).setTimes(Mockito.isNull(), Mockito.any(), Mockito.isNull());
		}
	}

	@Test
	public void testMapThrowsUnsupportedOperationException() throws IOException {
		Assertions.assertThrows(UnsupportedOperationException.class, () -> {
			inTest.map(MapMode.PRIVATE, 3727L, 3727L);
		});
	}

	@Nested
	public class Locking {

		private FileLock delegate = Mockito.mock(FileLock.class);

		@BeforeEach
		public void setup() {
			Mockito.when(options.readable()).thenReturn(true);

			Assumptions.assumeTrue(fileHeaderCryptor.headerSize() == 50);
			Assumptions.assumeTrue(fileContentCryptor.cleartextChunkSize() == 100);
			Assumptions.assumeTrue(fileContentCryptor.ciphertextChunkSize() == 110);
		}

		@ParameterizedTest(name = "beginOfChunk({0}) == {1}")
		@CsvSource({"0,50", "1,50", "99,50", "100,160", "199,160", "200,270", "300,380", "372,380", "399,380", "400,490", "4200,4670", "9223372036854775807,9223372036854775807"})
		@DisplayName("correctness of beginOfChunk()")
		public void testBeginOfChunk(long cleaertextPos, long expectedCiphertextPos) {
			long ciphertextPos = inTest.beginOfChunk(cleaertextPos);

			Assertions.assertEquals(expectedCiphertextPos, ciphertextPos);
		}

		@Test
		@DisplayName("unsuccessful tryLock()")
		public void testTryLockReturnsNullIfDelegateReturnsNull() throws IOException {
			when(ciphertextFileChannel.tryLock(Mockito.anyLong(), Mockito.anyLong(), Mockito.anyBoolean())).thenReturn(null);

			FileLock result = inTest.tryLock(372l, 3828l, true);

			Assertions.assertNull(result);
		}

		@Test
		@DisplayName("successful tryLock()")
		public void testTryLockReturnsCryptoFileLockWrappingDelegate() throws IOException {
			when(ciphertextFileChannel.tryLock(380l, 4670l + 110l - 380l, true)).thenReturn(delegate);

			FileLock result = inTest.tryLock(372l, 3828l, true);

			Assertions.assertNotNull(result);
			Assertions.assertTrue(result instanceof CleartextFileLock);
			CleartextFileLock cleartextFileLock = (CleartextFileLock) result;
			Assertions.assertEquals(inTest, cleartextFileLock.acquiredBy());
			Assertions.assertEquals(delegate, cleartextFileLock.delegate());
			Assertions.assertEquals(372l, cleartextFileLock.position());
			Assertions.assertEquals(3828l, cleartextFileLock.size());
		}

		@Test
		@DisplayName("successful lock()")
		public void testLockReturnsCryptoFileLockWrappingDelegate() throws IOException {
			when(ciphertextFileChannel.lock(380l, 4670l + 110l - 380l, true)).thenReturn(delegate);

			FileLock result = inTest.lock(372l, 3828l, true);

			Assertions.assertNotNull(result);
			Assertions.assertTrue(result instanceof CleartextFileLock);
			CleartextFileLock cleartextFileLock = (CleartextFileLock) result;
			Assertions.assertEquals(inTest, cleartextFileLock.acquiredBy());
			Assertions.assertEquals(delegate, cleartextFileLock.delegate());
			Assertions.assertEquals(372l, cleartextFileLock.position());
			Assertions.assertEquals(3828l, cleartextFileLock.size());
		}

	}

	@Nested
	public class Read {

		@Test
		public void testReadFailsIfNotReadable() throws IOException {
			var buf = ByteBuffer.allocate(10);
			when(options.readable()).thenReturn(false);

			Assertions.assertThrows(NonReadableChannelException.class, () -> {
				inTest.read(buf);
			});
		}

		@Test
		public void testReadFromMultipleChunks() throws IOException {
			fileSize.set(5_000_000_100l); // initial cleartext size will be 5_000_000_100l
			when(options.readable()).thenReturn(true);

			inTest = new CleartextFileChannel(ciphertextFileChannel, headerHolder, readWriteLock, cryptor, chunkCache, bufferPool, options, fileSize, lastModified, currentFilePath, exceptionsDuringWrite, closeListener, stats);
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
			inOrder.verify(chunkCache).getChunk(0l); // A
			inOrder.verify(chunkCache).getChunk(1l); // B
			inOrder.verify(chunkCache).getChunk(2l); // B
			inOrder.verify(chunkCache).getChunk(50_000_000l); // C
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
		@DisplayName("multiple writes to different chunks within the same file")
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
			inOrder.verify(chunkCache).getChunk(0l); // A
			inOrder.verify(chunkCache).putChunk(Mockito.eq(1l), Mockito.any()); // B
			inOrder.verify(chunkCache).putChunk(Mockito.eq(50l), Mockito.any()); // C
			inOrder.verifyNoMoreInteractions();
		}

		@Test
		@DisplayName("write to non-writable channel")
		public void testWriteFailsIfNotWritable() {
			var buf = ByteBuffer.allocate(10);
			when(options.writable()).thenReturn(false);

			Assertions.assertThrows(NonWritableChannelException.class, () -> {
				inTest.write(buf);
			});
		}

		@Test
		@DisplayName("test position increments")
		public void testWriteIncrementsPositionByAmountWritten() throws IOException {
			ByteBuffer buffer = ByteBuffer.allocate(110);
			when(options.writable()).thenReturn(true);

			Assertions.assertEquals(100, inTest.size());

			int written = inTest.write(buffer, 95); // old EOF at 100

			Assertions.assertEquals(110, written);
			Assertions.assertEquals(205, inTest.size());

			verify(chunkCache).getChunk(0l);
			verify(chunkCache).putChunk(Mockito.eq(1l), Mockito.any());
			verify(chunkCache).getChunk(2l);
		}

		@Test
		@DisplayName("write buffers to non-writable channel")
		public void testWriteWithBuffersFailsIfNotWritable() {
			when(options.writable()).thenReturn(false);

			Assertions.assertThrows(NonWritableChannelException.class, () -> {
				inTest.write(null, 0, 0);
			});
		}

		@Test
		@DisplayName("write subset of given buffers")
		public void testWriteWithBuffers() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(21), ByteBuffer.allocate(19), ByteBuffer.allocate(14)};
			when(options.writable()).thenReturn(true);

			inTest.position(70);

			long written = inTest.write(buffers, 1, 2);
			Assertions.assertEquals(40, written);
		}

		@Test
		@DisplayName("write at position greater than the file's size")
		public void writeAfterEof() throws IOException {
			Assumptions.assumeTrue(inTest.size() < 200);
			when(options.writable()).thenReturn(true);
			ByteBuffer buffer = ByteBuffer.allocate(10);

			long written = inTest.write(buffer, 200);

			Assertions.assertEquals(10l, written);
			Assertions.assertEquals(210l, inTest.size());
		}

		@Test
		@DisplayName("write header if it isn't already written")
		public void testWriteHeaderIfNeeded() throws IOException {
			when(options.writable()).thenReturn(true);

			when(headerIsPersisted.get()).thenReturn(false).thenReturn(true).thenReturn(true);

			inTest.force(true);
			inTest.force(true);
			inTest.force(true);

			Mockito.verify(ciphertextFileChannel, Mockito.times(1)).write(Mockito.any(), Mockito.eq(0l));
		}

		@Test
		@DisplayName("If writing header fails, it is indicated as not persistent")
		public void testWriteHeaderFailsResetsPersistenceState() throws IOException {
			when(options.writable()).thenReturn(true);
			when(headerIsPersisted.get()).thenReturn(false);
			doNothing().when(headerIsPersisted).set(anyBoolean());
			when(ciphertextFileChannel.write(any(), anyLong())).thenThrow(new IOException("writing failed"));

			Assertions.assertThrows(IOException.class, () -> inTest.force(true));

			Mockito.verify(ciphertextFileChannel, Mockito.times(1)).write(Mockito.any(), Mockito.eq(0l));
			Mockito.verify(headerIsPersisted, Mockito.never()).set(anyBoolean());
		}

		@Test
		@DisplayName("don't write header if it is already written")
		public void testDontRewriteHeader() throws IOException {
			when(options.writable()).thenReturn(true);
			when(headerIsPersisted.get()).thenReturn(true);
			inTest = new CleartextFileChannel(ciphertextFileChannel, headerHolder, readWriteLock, cryptor, chunkCache, bufferPool, options, fileSize, lastModified, currentFilePath, exceptionsDuringWrite, closeListener, stats);

			inTest.force(true);

			Mockito.verify(ciphertextFileChannel, Mockito.never()).write(Mockito.any(), Mockito.eq(0l));
		}

	}

	@Nested
	@DisplayName("on closed channel:")
	public class OperationsOnClosedChannelThrowClosedChannelException {

		@BeforeEach
		public void setUp() throws IOException {
			inTest.close();
		}

		@Test
		@DisplayName("position()")
		public void testGetPosition() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.position();
			});
		}

		@Test
		@DisplayName("position(pos)")
		public void testSetPosition() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.position(3727L);
			});
		}

		@Test
		@DisplayName("read(buf)")
		public void testRead() {
			var buf = ByteBuffer.allocate(10);
			when(options.readable()).thenReturn(true);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.read(buf);
			});
		}

		@Test
		@DisplayName("write(buf)")
		public void testWrite() {
			var buf = ByteBuffer.allocate(10);
			when(options.writable()).thenReturn(true);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.write(buf);
			});
		}

		@Test
		@DisplayName("read(buf, pos)")
		public void testReadWithPosition() {
			var buf = ByteBuffer.allocate(10);
			when(options.readable()).thenReturn(true);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.read(buf, 3727L);
			});
		}

		@Test
		@DisplayName("write(buf, pos)")
		public void testWriteWithPosition() {
			var buf = ByteBuffer.allocate(10);
			when(options.writable()).thenReturn(true);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.write(buf, 3727L);
			});
		}

		@Test
		@DisplayName("transferFrom(ch, offset, length)")
		public void testTransferFrom() throws IOException {
			when(options.readable()).thenReturn(true);
			ReadableByteChannel source = mock(ReadableByteChannel.class);
			when(source.read(any())).thenReturn(58);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.transferFrom(source, 3727L, 58);
			});
		}

		@Test
		@DisplayName("transferTo(offset, length, ch)")
		public void testTransferTo() throws IOException {
			when(options.readable()).thenReturn(true);
			WritableByteChannel target = mock(WritableByteChannel.class);
			when(target.write(any())).thenReturn(58);

			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.transferTo(3727L, 58, target);
			});
		}

		@Test
		@DisplayName("size()")
		public void testSize() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.size();
			});
		}

		@Test
		@DisplayName("truncate(size)")
		public void testTruncate() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.truncate(3727L);
			});
		}

		@Test
		@DisplayName("force(force)")
		public void testForce() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.force(true);
			});
		}

		@Test
		@DisplayName("lock(position, size, shared)")
		public void testLock() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.lock(3727L, 3727L, true);
			});
		}

		@Test
		@DisplayName("tryLock(position, size, shared)")
		public void testTryLock() {
			Assertions.assertThrows(ClosedChannelException.class, () -> {
				inTest.tryLock(3727L, 3727L, true);
			});
		}

	}

}
