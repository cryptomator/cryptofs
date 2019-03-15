package org.cryptomator.cryptofs.ch;

import de.bechte.junit.runners.context.HierarchicalContextRunner;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

@RunWith(HierarchicalContextRunner.class)
public class CleartextFileChannelTest {

	private static final long EOF = -1;

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private ChunkCache chunkCache = mock(ChunkCache.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private FileContentCryptor fileContentCryptor = mock(FileContentCryptor.class);
	private FileChannel ciphertextFileChannel = mock(FileChannel.class);
	private Lock lock = mock(Lock.class);
	private EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
	private AtomicLong fileSize = new AtomicLong(100);
	private ExceptionsDuringWrite exceptionsDuringWrite = mock(ExceptionsDuringWrite.class);

	private CleartextFileChannel inTest;

	@Before
	public void setUp() throws IOException {
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		when(chunkCache.get(Mockito.anyLong())).then(invocation ->  ChunkData.wrap(ByteBuffer.allocate(100)));
		when(fileHeaderCryptor.headerSize()).thenReturn(50);
		when(fileContentCryptor.cleartextChunkSize()).thenReturn(100);
		when(fileContentCryptor.ciphertextChunkSize()).thenReturn(110);
		when(ciphertextFileChannel.size()).thenReturn(160l); // initial cleartext size will be 100

		inTest = new CleartextFileChannel(lock, ciphertextFileChannel, cryptor, chunkCache, options, fileSize, exceptionsDuringWrite);
	}

	@Test
	public void testSize() throws IOException {
		Assert.assertEquals(100, inTest.size());
	}

	public class Position {

		@Test
		public void testInitialPositionIsZero() throws IOException {
			assertThat(inTest.position(), is(0L));
		}

		@Test
		public void testPositionCanBeSet() throws IOException {
			inTest.position(3727L);

			assertThat(inTest.position(), is(3727L));
		}

		@Test
		public void testPositionCanNotBeSetToANegativeValue() throws IOException {
			thrown.expect(IllegalArgumentException.class);

			inTest.position(-42);
		}

	}

	public class Truncate {

		@Test
		public void testTruncateFailsWithIOExceptionIfNotWritable() throws IOException {
			when(options.writable()).thenReturn(false);

			thrown.expect(NonWritableChannelException.class);

			inTest.truncate(3727L);
		}

		@Test
		public void testTruncateKeepsPositionIfNewSizeGreaterCurrentPosition() throws IOException {
			long newSize = 442;
			long currentPosition = 342;
			inTest.position(currentPosition);
			when(options.writable()).thenReturn(true);

			inTest.truncate(newSize);

			assertThat(inTest.position(), is(currentPosition));
		}

		@Test
		public void testTruncateSetsPositionToNewSizeIfSmallerCurrentPosition() throws IOException {
			inTest.position(90);
			when(options.writable()).thenReturn(true);

			inTest.truncate(50);

			Assert.assertEquals(50, inTest.position());
		}

	}

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

			thrown.expect(IOException.class);
			thrown.expectMessage("exception during write");
			inTest.force(false);

			verify(chunkCache).invalidateAll();
		}

	}

	public class Close {

		@Test
		public void testCloseReleasesLock() throws IOException {
			inTest.implCloseChannel();

			verify(lock).unlock();
		}
	}

	@Test
	public void testMapThrowsUnsupportedOperationException() throws IOException {
		thrown.expect(UnsupportedOperationException.class);

		inTest.map(MapMode.PRIVATE, 3727L, 3727L);
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

	public class Read {

		@Test
		public void testReadFailsIfNotReadable() throws IOException {
			when(options.readable()).thenReturn(false);

			thrown.expect(NonReadableChannelException.class);

			inTest.read(ByteBuffer.allocate(10));
		}

		@Test
		public void testReadFromMultipleChunks() throws IOException {
			when(ciphertextFileChannel.size()).thenReturn(5_500_000_160l); // initial cleartext size will be 5_000_000_100l
			when(options.readable()).thenReturn(true);

			inTest = new CleartextFileChannel(lock, ciphertextFileChannel, cryptor, chunkCache, options, fileSize, exceptionsDuringWrite);
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

			Assert.assertEquals(66, inTest.position());
		}

		@Test
		public void testReadDoesNotChangePositionOnEof() throws IOException {
			ByteBuffer buffer = ByteBuffer.allocate(10);
			inTest.position(100);
			when(options.readable()).thenReturn(true);

			inTest.read(buffer);

			Assert.assertEquals(100, inTest.position());
		}

		@Test
		public void testReadWithBuffersFailsIfChannelNotReadable() throws IOException {
			ByteBuffer[] irrelevant = null;
			when(options.readable()).thenReturn(false);

			thrown.expect(NonReadableChannelException.class);

			inTest.read(irrelevant, 0, 0);
		}

		@Test
		public void testReadWithBuffersDoesReadNothingWhenLengthIsZero() throws IOException {
			ByteBuffer[] buffers = new ByteBuffer[10];
			when(options.readable()).thenReturn(true);

			long read = inTest.read(buffers, 3, 0);

			assertThat(read, is(0L));
			verifyZeroInteractions(chunkCache);
		}

		@Test
		public void testReadWithBuffersReturnsEofIfHitOnFirstRead() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(10), ByteBuffer.allocate(10)};
			when(options.readable()).thenReturn(true);

			inTest.position(100); // EOF at 100
			long read = inTest.read(buffers, 0, 3);

			assertThat(read, is(EOF));
		}

		@Test
		public void testReadWithBuffersAbortsIfEofIsHitAfterFirstRead() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(10), ByteBuffer.allocate(10)};
			when(options.readable()).thenReturn(true);

			inTest.position(90); // EOF at 100
			long read = inTest.read(buffers, 0, 3);

			Assert.assertEquals(10, read);
		}

		@Test
		public void testReadWithBuffersReadsWithoutHittingEof() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(10), ByteBuffer.allocate(10)};
			when(options.readable()).thenReturn(true);

			inTest.position(0); // EOF at 100
			long read = inTest.read(buffers, 0, 3);

			Assert.assertEquals(30, read);
		}

	}

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

			thrown.expect(NonWritableChannelException.class);

			inTest.write(ByteBuffer.allocate(10));
		}

		@Test
		public void testWriteIncrementsPositionByAmountWritten() throws IOException {
			ByteBuffer buffer = ByteBuffer.allocate(110);
			when(options.writable()).thenReturn(true);

			Assert.assertEquals(100, inTest.size());

			int written = inTest.write(buffer, 95); // old EOF at 100

			Assert.assertEquals(110, written);
			Assert.assertEquals(205, inTest.size());

			verify(chunkCache).get(0l);
			verify(chunkCache).set(Mockito.eq(1l), Mockito.any());
			verify(chunkCache).get(2l);
		}

		@Test
		public void testWriteWithBuffersFailsIfNotWritable() throws IOException {
			ByteBuffer[] irrelevant = null;
			when(options.writable()).thenReturn(false);

			thrown.expect(NonWritableChannelException.class);

			inTest.write(irrelevant, 0, 0);
		}

		@Test
		public void testWriteWithBuffersStartsWritingFromOffsetAndWritesLengthBuffers() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(21), ByteBuffer.allocate(19), ByteBuffer.allocate(14)};
			when(options.writable()).thenReturn(true);

			inTest.position(70);

			long written = inTest.write(buffers, 1, 2);
			Assert.assertEquals(40, written);
		}

	}

//	public class TransferTo {
//
//		@Test
//		public void testTransferToFailsIfChannelNotReadable() throws IOException {
//			WritableByteChannel irrelevant = null;
//			when(options.readable()).thenReturn(false);
//
//			thrown.expect(NonReadableChannelException.class);
//
//			inTest.transferTo(0L, 0L, irrelevant);
//		}
//
//		@Test
//		public void testTransferToTransfersCountDataStartingFromPosition() throws IOException {
//			long startTransferFrom = 6042;
//			long transferAmount = 23000;
//			ReadAndWritableBytes sourceData = ReadAndWritableBytes.random((int) (startTransferFrom + transferAmount));
//			when(options.readable()).thenReturn(true);
//			when(openCryptoFile.read(any(ByteBuffer.class), anyLong())).thenAnswer(invocation -> {
//				ByteBuffer target = invocation.getArgument(0);
//				Long position = invocation.getArgument(1);
//				return sourceData.read(target, position);
//			});
//			ReadAndWritableBytes targetData = ReadAndWritableBytes.empty();
//
//			long amount = inTest.transferTo(startTransferFrom, transferAmount, targetData);
//
//			assertThat(amount, is(transferAmount));
//			assertThat(targetData.toArray(), is(sourceData.toArray((int) startTransferFrom, (int) transferAmount)));
//		}
//
//		@Test
//		public void testTransferToTransfersAllRemainingBytesIfCountIsGreater() throws IOException {
//			long startTransferFrom = 6042;
//			long transferAmount = 23000;
//			long remainingAmount = 10000;
//			ReadAndWritableBytes sourceData = ReadAndWritableBytes.random((int) (startTransferFrom + remainingAmount));
//			when(options.readable()).thenReturn(true);
//			when(openCryptoFile.read(any(ByteBuffer.class), anyLong())).thenAnswer(invocation -> {
//				ByteBuffer target = invocation.getArgument(0);
//				Long position = invocation.getArgument(1);
//				return sourceData.read(target, position);
//			});
//			ReadAndWritableBytes targetData = ReadAndWritableBytes.empty();
//
//			long amount = inTest.transferTo(startTransferFrom, transferAmount, targetData);
//
//			assertThat(amount, is(remainingAmount));
//			assertThat(targetData.toArray(), is(sourceData.toArray((int) startTransferFrom, (int) remainingAmount)));
//		}
//
//	}
//
//	public class TransferFrom {
//
//		@Test
//		public void testTransferFromFailsIfChannelNotWritable() throws IOException {
//			ReadableByteChannel irrelevant = null;
//			when(options.writable()).thenReturn(false);
//
//			thrown.expect(NonWritableChannelException.class);
//
//			inTest.transferFrom(irrelevant, 0L, 0L);
//		}
//
//		@Test
//		public void testTransferFromTransfersNothingIfPositionGreaterSize() throws IOException {
//			long position = 5000;
//			long size = position - 100;
//			ReadAndWritableBytes sourceData = ReadAndWritableBytes.random(1000);
//			when(options.writable()).thenReturn(true);
//
//			long amount = inTest.transferFrom(sourceData, position, 150);
//
//			assertThat(amount, is(0L));
//		}
//
//		@Test
//		public void testTransferFromTransfersCountBytesStartingAtPosition() throws IOException {
//			long startTransferAt = 6042;
//			long transferAmount = 23000;
//			ReadAndWritableBytes sourceData = ReadAndWritableBytes.random((int) (transferAmount));
//			ReadAndWritableBytes targetData = ReadAndWritableBytes.empty();
//			when(options.writable()).thenReturn(true);
//			when(openCryptoFile.size()).thenReturn(startTransferAt);
//			when(openCryptoFile.write(same(options), any(ByteBuffer.class), anyLong())).thenAnswer(invocation -> {
//				ByteBuffer source = invocation.getArgument(1);
//				Long position = invocation.getArgument(2);
//				return targetData.write(source, position.intValue());
//			});
//
//			long amount = inTest.transferFrom(sourceData, startTransferAt, transferAmount);
//
//			assertThat(amount, is(transferAmount));
//			assertThat(sourceData.toArray(), is(targetData.toArray((int) startTransferAt, (int) transferAmount)));
//		}
//
//		@Test
//		public void testTransferFromTransfersRemainingBytesIfLessThanCount() throws IOException {
//			long startTransferAt = 6042;
//			long transferAmount = 23000;
//			long remainingAmount = 15000;
//			ReadAndWritableBytes sourceData = ReadAndWritableBytes.random((int) (remainingAmount));
//			ReadAndWritableBytes targetData = ReadAndWritableBytes.empty();
//			when(options.writable()).thenReturn(true);
//			when(openCryptoFile.size()).thenReturn(startTransferAt);
//			when(openCryptoFile.write(same(options), any(ByteBuffer.class), anyLong())).thenAnswer(invocation -> {
//				ByteBuffer source = invocation.getArgument(1);
//				Long position = invocation.getArgument(2);
//				return targetData.write(source, position.intValue());
//			});
//
//			long amount = inTest.transferFrom(sourceData, startTransferAt, transferAmount);
//
//			assertThat(amount, is(remainingAmount));
//			assertThat(sourceData.toArray(), is(targetData.toArray((int) startTransferAt, (int) remainingAmount)));
//		}
//
//	}

	public class OperationsOnClosedChannelThrowClosedChannelException {

		@Before
		public void setUp() throws IOException {
			inTest.close();
			thrown.expect(ClosedChannelException.class);
		}

		@Test
		public void testGetPosition() throws IOException {
			inTest.position();
		}

		@Test
		public void testSetPosition() throws IOException {
			inTest.position(3727L);
		}

		@Test
		public void testRead() throws IOException {
			when(options.readable()).thenReturn(true);

			inTest.read(ByteBuffer.allocate(10));
		}

		@Test
		public void testWrite() throws IOException {
			when(options.writable()).thenReturn(true);

			inTest.write(ByteBuffer.allocate(10));
		}

		@Test
		public void testReadWithPosition() throws IOException {
			when(options.readable()).thenReturn(true);

			inTest.read(ByteBuffer.allocate(10), 3727L);
		}

		@Test
		public void testWriteWithPosition() throws IOException {
			when(options.writable()).thenReturn(true);

			inTest.write(ByteBuffer.allocate(10), 3727L);
		}

		@Test
		public void testTransferFrom() throws IOException {
			when(options.readable()).thenReturn(true);
			ReadableByteChannel source = mock(ReadableByteChannel.class);
			when(source.read(any())).thenReturn(58);

			inTest.transferFrom(source, 3727L, 58);
		}

		@Test
		public void testTransferTo() throws IOException {
			when(options.readable()).thenReturn(true);
			WritableByteChannel target = mock(WritableByteChannel.class);
			when(target.write(any())).thenReturn(58);

			inTest.transferTo(3727L, 58, target);
		}

		@Test
		public void testSize() throws IOException {
			inTest.size();
		}

		@Test
		public void testTruncate() throws IOException {
			inTest.truncate(3727L);
		}

		@Test
		public void testForce() throws IOException {
			inTest.force(true);
		}

		@Test
		public void testLock() throws IOException {
			inTest.lock(3727L, 3727L, true);
		}

		@Test
		public void testTryLock() throws IOException {
			inTest.tryLock(3727L, 3727L, true);
		}

	}

}
