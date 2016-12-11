package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel.MapMode;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.function.Consumer;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.mockito.stubbing.Answer;

import de.bechte.junit.runners.context.HierarchicalContextRunner;

@RunWith(HierarchicalContextRunner.class)
public class CryptoFileChannelTest {

	private static final long ANY_POSITIVE_LONG = 3727L;
	private static final long ANY_NEGATIVE_LONG = -32L;

	private static final int ANY_POSITIVE_INT = 58;

	private static final long EOF = -1;

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class);

	private EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);

	@SuppressWarnings("unchecked")
	private Consumer<CryptoFileChannel> onClose = mock(Consumer.class);

	private FinallyUtil finallyUtil = mock(FinallyUtil.class);

	private CryptoFileChannel inTest;

	@Before
	public void setUp() throws IOException {
		inTest = new CryptoFileChannel(openCryptoFile, options, onClose, finallyUtil);
	}

	@Test
	public void testConstructorPassesOptionsToOpenCryptoFilesOpenMethod() throws IOException {
		verify(openCryptoFile).open(options);
	}

	@Test
	public void testFlyTroughFromBlockingIo() throws IOException {
		IOException e = new IOException();
		ByteBuffer buffer = ByteBuffer.allocate(100);
		when(openCryptoFile.read(buffer, 0)).thenThrow(e);
		when(options.readable()).thenReturn(true);

		thrown.expect(sameInstance(e));

		inTest.read(buffer);
	}

	public class Position {

		@Test
		public void testInitialPositionIsZero() throws IOException {
			assertThat(inTest.position(), is(0L));
		}

		@Test
		public void testPositionCanBeSet() throws IOException {
			inTest.position(ANY_POSITIVE_LONG);

			assertThat(inTest.position(), is(ANY_POSITIVE_LONG));
		}

		@Test
		public void testPositionCanNotBeSetToANegativeValue() throws IOException {
			thrown.expect(IllegalArgumentException.class);

			inTest.position(ANY_NEGATIVE_LONG);
		}

	}

	@Test
	public void testSizeDelegatesToOpenCryptoFile() throws ClosedChannelException {
		long expectedSize = 3823;

		when(openCryptoFile.size()).thenReturn(expectedSize);

		assertThat(inTest.size(), is(expectedSize));
	}

	public class Truncate {

		@Test
		public void testTruncateFailsWithIOExceptionIfNotWritable() throws IOException {
			when(options.writable()).thenReturn(false);

			thrown.expect(IOException.class);
			thrown.expectMessage("not writable");

			inTest.truncate(ANY_POSITIVE_LONG);
		}

		@Test
		public void testTruncateDelegatesToOpenCryptoFile() throws IOException {
			long expectedSize = 342;
			when(options.writable()).thenReturn(true);

			inTest.truncate(expectedSize);

			verify(openCryptoFile).truncate(expectedSize);
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
			long newSize = 242;
			long currentPosition = 342;
			inTest.position(currentPosition);
			when(options.writable()).thenReturn(true);

			inTest.truncate(newSize);

			assertThat(inTest.position(), is(newSize));
		}

	}

	public class Force {

		@Test
		public void testForceDelegatesToOpenCryptoFileWithTrue() throws IOException {
			inTest.force(true);

			verify(openCryptoFile).force(true, options);
		}

		@Test
		public void testForceDelegatesToOpenCryptoFileWithFalse() throws IOException {
			inTest.force(false);

			verify(openCryptoFile).force(false, options);
		}

	}

	@Test
	public void testMapThrowsUnsupportedOperationException() throws IOException {
		thrown.expect(UnsupportedOperationException.class);

		inTest.map(MapMode.PRIVATE, ANY_POSITIVE_LONG, ANY_POSITIVE_LONG);
	}

	public class Lock {

		@Test
		public void testTryLockReturnsNullIfDelegateReturnsNull() throws IOException {
			boolean shared = true;
			long position = 372L;
			long size = 3828L;
			when(openCryptoFile.tryLock(position, size, shared)).thenReturn(null);

			FileLock result = inTest.tryLock(position, size, shared);

			assertThat(result, is(nullValue()));
		}

		@Test
		public void testTryLockReturnsCryptoFileLockWrappingDelegate() throws IOException {
			boolean shared = true;
			long position = 372L;
			long size = 3828L;
			FileLock delegate = mock(FileLock.class);
			when(openCryptoFile.tryLock(position, size, shared)).thenReturn(delegate);

			FileLock result = inTest.tryLock(position, size, shared);

			assertThat(result, is(instanceOf(CryptoFileLock.class)));
			CryptoFileLock cryptoFileLock = (CryptoFileLock) result;
			assertThat(cryptoFileLock.acquiredBy(), is(inTest));
			assertThat(cryptoFileLock.delegate(), is(delegate));
			assertThat(cryptoFileLock.isShared(), is(shared));
			assertThat(cryptoFileLock.position(), is(position));
			assertThat(cryptoFileLock.size(), is(size));
		}

		@Test
		public void tesLockReturnsCryptoFileLockWrappingDelegate() throws IOException {
			boolean shared = true;
			long position = 372L;
			long size = 3828L;
			FileLock delegate = mock(FileLock.class);
			when(openCryptoFile.lock(position, size, shared)).thenReturn(delegate);

			FileLock result = inTest.lock(position, size, shared);

			assertThat(result, is(instanceOf(CryptoFileLock.class)));
			CryptoFileLock cryptoFileLock = (CryptoFileLock) result;
			assertThat(cryptoFileLock.acquiredBy(), is(inTest));
			assertThat(cryptoFileLock.delegate(), is(delegate));
			assertThat(cryptoFileLock.isShared(), is(shared));
			assertThat(cryptoFileLock.position(), is(position));
			assertThat(cryptoFileLock.size(), is(size));
		}

	}

	public class Read {

		@Test
		public void testReadFailsIfNotReadable() throws IOException {
			when(options.readable()).thenReturn(false);

			thrown.expect(IOException.class);
			thrown.expectMessage("not readable");

			inTest.read(ByteBuffer.allocate(10));
		}

		@Test
		public void testReadDelegatesToOpenCryptoFile() throws IOException {
			int amountRead = 82;
			long initialPosition = 382L;
			ByteBuffer buffer = ByteBuffer.allocate(ANY_POSITIVE_INT);
			inTest.position(initialPosition);
			when(options.readable()).thenReturn(true);
			when(openCryptoFile.read(buffer, initialPosition)).thenReturn(amountRead);

			int result = inTest.read(buffer);

			assertThat(result, is(amountRead));
		}

		@Test
		public void testReadIncrementsPositionByAmountRead() throws IOException {
			int amountRead = 82;
			long initialPosition = 382L;
			ByteBuffer buffer = ByteBuffer.allocate(ANY_POSITIVE_INT);
			inTest.position(initialPosition);
			when(options.readable()).thenReturn(true);
			when(openCryptoFile.read(buffer, initialPosition)).thenReturn(amountRead);

			inTest.read(buffer);

			assertThat(inTest.position(), is(initialPosition + amountRead));
		}

		@Test
		public void testReadWithPositionDelegatesToOpenCryptoFile() throws IOException {
			int amountRead = 82;
			long position = 382L;
			ByteBuffer buffer = ByteBuffer.allocate(ANY_POSITIVE_INT);
			inTest.position(ANY_POSITIVE_LONG);
			when(options.readable()).thenReturn(true);
			when(openCryptoFile.read(buffer, position)).thenReturn(amountRead);

			int result = inTest.read(buffer, position);

			assertThat(result, is(amountRead));
		}

		@Test
		public void testReadDoesNotChangePositionOnEof() throws IOException {
			int amountRead = -1;
			long initialPosition = 382L;
			ByteBuffer buffer = ByteBuffer.allocate(ANY_POSITIVE_INT);
			inTest.position(initialPosition);
			when(options.readable()).thenReturn(true);
			when(openCryptoFile.read(buffer, initialPosition)).thenReturn(amountRead);

			inTest.read(buffer);

			assertThat(inTest.position(), is(initialPosition));
		}

		@Test
		public void testReadWithBuffersFailsIfChannelNotReadable() throws IOException {
			ByteBuffer[] irrelevant = null;
			when(options.readable()).thenReturn(false);

			thrown.expect(IOException.class);
			thrown.expectMessage("not readable");

			inTest.read(irrelevant, 0, 0);
		}

		@Test
		public void testReadWithBuffersDoesReadNothingWhenLengthIsZero() throws IOException {
			ByteBuffer[] buffers = new ByteBuffer[10];
			when(options.readable()).thenReturn(true);

			long read = inTest.read(buffers, 3, 0);

			assertThat(read, is(0L));
			verify(openCryptoFile, never()).read(any(ByteBuffer.class), anyLong());
		}

		@Test
		public void testReadWithBuffersReturnsEofIfHitOnFirstRead() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(10), ByteBuffer.allocate(10)};
			when(options.readable()).thenReturn(true);
			long position = 349L;
			inTest.position(position);
			when(openCryptoFile.read(buffers[0], position)).thenReturn((int) EOF);

			long read = inTest.read(buffers, 0, 3);

			assertThat(read, is(EOF));
			verify(openCryptoFile).read(buffers[0], position);
			verify(openCryptoFile, never()).read(same(buffers[1]), anyLong());
			verify(openCryptoFile, never()).read(same(buffers[2]), anyLong());
		}

		@Test
		public void testReadWithBuffersAbortsIfEofIsHitAfterFirstRead() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(10), ByteBuffer.allocate(10)};
			when(options.readable()).thenReturn(true);
			long position = 349L;
			long amountRead = 10;
			inTest.position(position);
			when(openCryptoFile.read(buffers[0], position)).thenReturn((int) amountRead);
			when(openCryptoFile.read(buffers[1], position + amountRead)).thenReturn((int) EOF);

			long read = inTest.read(buffers, 0, 3);

			assertThat(read, is(amountRead));
			verify(openCryptoFile).read(buffers[0], position);
			verify(openCryptoFile).read(buffers[1], position + amountRead);
			verify(openCryptoFile, never()).read(same(buffers[2]), anyLong());
		}

		@Test
		public void testReadWithBuffersReadsFromLengthBuffersIfEofIsNotHit() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(10), ByteBuffer.allocate(10), ByteBuffer.allocate(10)};
			when(options.readable()).thenReturn(true);
			long position = 349L;
			long firstAmountRead = 23;
			long secondAmountRead = 19;
			inTest.position(position);
			when(openCryptoFile.read(buffers[1], position)).thenReturn((int) firstAmountRead);
			when(openCryptoFile.read(buffers[2], position + firstAmountRead)).thenReturn((int) secondAmountRead);

			long read = inTest.read(buffers, 1, 2);

			assertThat(read, is(firstAmountRead + secondAmountRead));
			verify(openCryptoFile, never()).read(same(buffers[0]), anyLong());
			verify(openCryptoFile).read(buffers[1], position);
			verify(openCryptoFile).read(buffers[2], position + firstAmountRead);
			verify(openCryptoFile, never()).read(same(buffers[3]), anyLong());
		}

	}

	public class Write {

		@Test
		public void testWriteFailsIfNotWritable() throws IOException {
			when(options.writable()).thenReturn(false);

			thrown.expect(IOException.class);
			thrown.expectMessage("not writable");

			inTest.write(ByteBuffer.allocate(10));
		}

		@Test
		public void testWriteDelegatesToOpenCryptoFile() throws IOException {
			int amountWritten = 82;
			long initialPosition = 382L;
			ByteBuffer buffer = ByteBuffer.allocate(ANY_POSITIVE_INT);
			inTest.position(initialPosition);
			when(options.writable()).thenReturn(true);
			when(openCryptoFile.write(options, buffer, initialPosition)).thenReturn(amountWritten);

			int result = inTest.write(buffer);

			assertThat(result, is(amountWritten));
		}

		@Test
		public void testWriteAppendsIfInAppendMode() throws IOException {
			int amountWritten = 82;
			ByteBuffer buffer = ByteBuffer.allocate(ANY_POSITIVE_INT);
			when(options.writable()).thenReturn(true);
			when(options.append()).thenReturn(true);
			when(openCryptoFile.append(options, buffer)).thenReturn((long) amountWritten);

			int result = inTest.write(buffer);

			assertThat(result, is(amountWritten));
		}

		@Test
		public void testWriteWithPositionDelegatesToOpenCryptoFile() throws IOException {
			int amountWritten = 82;
			long position = 382L;
			ByteBuffer buffer = ByteBuffer.allocate(ANY_POSITIVE_INT);
			inTest.position(ANY_POSITIVE_LONG);
			when(options.writable()).thenReturn(true);
			when(openCryptoFile.write(options, buffer, position)).thenReturn(amountWritten);

			int result = inTest.write(buffer, position);

			assertThat(result, is(amountWritten));
		}

		@Test
		public void testWriteIncrementsPositionByAmountWritten() throws IOException {
			int amountWritten = 82;
			long initialPosition = 382L;
			ByteBuffer buffer = ByteBuffer.allocate(ANY_POSITIVE_INT);
			inTest.position(initialPosition);
			when(options.writable()).thenReturn(true);
			when(openCryptoFile.write(options, buffer, initialPosition)).thenReturn(amountWritten);

			inTest.write(buffer);

			assertThat(inTest.position(), is(initialPosition + amountWritten));
		}

		@Test
		public void testWriteWithBuffersFailsIfNotWritable() throws IOException {
			ByteBuffer[] irrelevant = null;
			when(options.writable()).thenReturn(false);

			thrown.expect(IOException.class);
			thrown.expectMessage("not writable");

			inTest.write(irrelevant, 0, 0);
		}

		@Test
		public void testWriteWithBuffersStartsWritingFromOffsetAndWritesLengthBuffers() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(21), ByteBuffer.allocate(19), ByteBuffer.allocate(14)};
			long position = 348L;
			long firstWritten = 21L;
			long secondWritten = 19L;
			inTest.position(position);
			when(openCryptoFile.write(options, buffers[1], position)).thenReturn((int) firstWritten);
			when(openCryptoFile.write(options, buffers[2], position + firstWritten)).thenReturn((int) secondWritten);
			when(options.writable()).thenReturn(true);

			inTest.write(buffers, 1, 2);

			verify(openCryptoFile, never()).write(same(options), same(buffers[0]), anyLong());
			verify(openCryptoFile).write(options, buffers[1], position);
			verify(openCryptoFile).write(options, buffers[2], position + firstWritten);
			verify(openCryptoFile, never()).write(same(options), same(buffers[3]), anyLong());
		}

		@Test
		public void testWriteWithBuffersAppendsIfInAppendMode() throws IOException {
			ByteBuffer[] buffers = {ByteBuffer.allocate(10), ByteBuffer.allocate(21), ByteBuffer.allocate(19), ByteBuffer.allocate(14)};
			long firstWritten = 21L;
			long secondWritten = 19L;
			when(openCryptoFile.append(options, buffers[1])).thenReturn(firstWritten);
			when(openCryptoFile.append(options, buffers[2])).thenReturn(secondWritten);
			when(options.writable()).thenReturn(true);
			when(options.append()).thenReturn(true);

			inTest.write(buffers, 1, 2);

			InOrder inOrder = inOrder(openCryptoFile);
			inOrder.verify(openCryptoFile).append(options, buffers[1]);
			inOrder.verify(openCryptoFile).append(options, buffers[2]);
			verify(openCryptoFile, never()).append(options, buffers[0]);
			verify(openCryptoFile, never()).append(options, buffers[3]);
		}

	}

	public class TransferTo {

		@Test
		public void testTransferToFailsIfChannelNotReadable() throws IOException {
			WritableByteChannel irrelevant = null;
			when(options.readable()).thenReturn(false);

			thrown.expect(IOException.class);
			thrown.expectMessage("not readable");

			inTest.transferTo(0L, 0L, irrelevant);
		}

		@Test
		public void testTransferToTransfersCountDataStartingFromPosition() throws IOException {
			long startTransferFrom = 6042;
			long transferAmount = 23000;
			ReadAndWritableBytes sourceData = ReadAndWritableBytes.random((int) (startTransferFrom + transferAmount));
			when(options.readable()).thenReturn(true);
			when(openCryptoFile.read(any(ByteBuffer.class), anyLong())).thenAnswer(new Answer<Integer>() {
				@Override
				public Integer answer(InvocationOnMock invocation) throws Throwable {
					ByteBuffer target = invocation.getArgumentAt(0, ByteBuffer.class);
					Long position = invocation.getArgumentAt(1, Long.class);
					return sourceData.read(target, position);
				}
			});
			ReadAndWritableBytes targetData = ReadAndWritableBytes.empty();

			long amount = inTest.transferTo(startTransferFrom, transferAmount, targetData);

			assertThat(amount, is(transferAmount));
			assertThat(targetData.toArray(), is(sourceData.toArray((int) startTransferFrom, (int) transferAmount)));
		}

		@Test
		public void testTransferToTransfersAllRemainingBytesIfCountIsGreater() throws IOException {
			long startTransferFrom = 6042;
			long transferAmount = 23000;
			long remainingAmount = 10000;
			ReadAndWritableBytes sourceData = ReadAndWritableBytes.random((int) (startTransferFrom + remainingAmount));
			when(options.readable()).thenReturn(true);
			when(openCryptoFile.read(any(ByteBuffer.class), anyLong())).thenAnswer(new Answer<Integer>() {
				@Override
				public Integer answer(InvocationOnMock invocation) throws Throwable {
					ByteBuffer target = invocation.getArgumentAt(0, ByteBuffer.class);
					Long position = invocation.getArgumentAt(1, Long.class);
					return sourceData.read(target, position);
				}
			});
			ReadAndWritableBytes targetData = ReadAndWritableBytes.empty();

			long amount = inTest.transferTo(startTransferFrom, transferAmount, targetData);

			assertThat(amount, is(remainingAmount));
			assertThat(targetData.toArray(), is(sourceData.toArray((int) startTransferFrom, (int) remainingAmount)));
		}

	}

	public class TransferFrom {

		@Test
		public void testTransferFromFailsIfChannelNotWritable() throws IOException {
			ReadableByteChannel irrelevant = null;
			when(options.writable()).thenReturn(false);

			thrown.expect(IOException.class);
			thrown.expectMessage("not writable");

			inTest.transferFrom(irrelevant, 0L, 0L);
		}

		@Test
		public void testTransferFromTransfersNothingIfPositionGreaterSize() throws IOException {
			long position = 5000;
			long size = position - 100;
			ReadAndWritableBytes sourceData = ReadAndWritableBytes.random(1000);
			when(options.writable()).thenReturn(true);
			when(openCryptoFile.size()).thenReturn(size);

			long amount = inTest.transferFrom(sourceData, position, 150);

			assertThat(amount, is(0L));
		}

		@Test
		public void testTransferFromTransfersCountBytesStartingAtPosition() throws IOException {
			long startTransferAt = 6042;
			long transferAmount = 23000;
			ReadAndWritableBytes sourceData = ReadAndWritableBytes.random((int) (transferAmount));
			ReadAndWritableBytes targetData = ReadAndWritableBytes.empty();
			when(options.writable()).thenReturn(true);
			when(openCryptoFile.size()).thenReturn(startTransferAt);
			when(openCryptoFile.write(same(options), any(ByteBuffer.class), anyLong())).thenAnswer(new Answer<Integer>() {
				@Override
				public Integer answer(InvocationOnMock invocation) throws Throwable {
					ByteBuffer source = invocation.getArgumentAt(1, ByteBuffer.class);
					Long position = invocation.getArgumentAt(2, Long.class);
					return targetData.write(source, position.intValue());
				}
			});

			long amount = inTest.transferFrom(sourceData, startTransferAt, transferAmount);

			assertThat(amount, is(transferAmount));
			assertThat(sourceData.toArray(), is(targetData.toArray((int) startTransferAt, (int) transferAmount)));
		}

		@Test
		public void testTransferFromTransfersRemainingBytesIfLessThanCount() throws IOException {
			long startTransferAt = 6042;
			long transferAmount = 23000;
			long remainingAmount = 15000;
			ReadAndWritableBytes sourceData = ReadAndWritableBytes.random((int) (remainingAmount));
			ReadAndWritableBytes targetData = ReadAndWritableBytes.empty();
			when(options.writable()).thenReturn(true);
			when(openCryptoFile.size()).thenReturn(startTransferAt);
			when(openCryptoFile.write(same(options), any(ByteBuffer.class), anyLong())).thenAnswer(new Answer<Integer>() {
				@Override
				public Integer answer(InvocationOnMock invocation) throws Throwable {
					ByteBuffer source = invocation.getArgumentAt(1, ByteBuffer.class);
					Long position = invocation.getArgumentAt(2, Long.class);
					return targetData.write(source, position.intValue());
				}
			});

			long amount = inTest.transferFrom(sourceData, startTransferAt, transferAmount);

			assertThat(amount, is(remainingAmount));
			assertThat(sourceData.toArray(), is(targetData.toArray((int) startTransferAt, (int) remainingAmount)));
		}

	}

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
			inTest.position(ANY_POSITIVE_LONG);
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

			inTest.read(ByteBuffer.allocate(10), ANY_POSITIVE_LONG);
		}

		@Test
		public void testWriteWithPosition() throws IOException {
			when(options.writable()).thenReturn(true);

			inTest.write(ByteBuffer.allocate(10), ANY_POSITIVE_LONG);
		}

		@Test
		public void testTransferFrom() throws IOException {
			when(options.readable()).thenReturn(true);
			ReadableByteChannel source = mock(ReadableByteChannel.class);
			when(source.read(any())).thenReturn(ANY_POSITIVE_INT);

			inTest.transferFrom(source, ANY_POSITIVE_LONG, ANY_POSITIVE_INT);
		}

		@Test
		public void testTransferTo() throws IOException {
			when(options.readable()).thenReturn(true);
			WritableByteChannel target = mock(WritableByteChannel.class);
			when(target.write(any())).thenReturn(ANY_POSITIVE_INT);

			inTest.transferTo(ANY_POSITIVE_LONG, ANY_POSITIVE_INT, target);
		}

		@Test
		public void testSize() throws IOException {
			inTest.size();
		}

		@Test
		public void testTruncate() throws IOException {
			inTest.truncate(ANY_POSITIVE_LONG);
		}

		@Test
		public void testForce() throws IOException {
			inTest.force(true);
		}

		@Test
		public void testLock() throws IOException {
			inTest.lock(ANY_POSITIVE_LONG, ANY_POSITIVE_LONG, true);
		}

		@Test
		public void testTryLock() throws IOException {
			inTest.tryLock(ANY_POSITIVE_LONG, ANY_POSITIVE_LONG, true);
		}

	}

}
