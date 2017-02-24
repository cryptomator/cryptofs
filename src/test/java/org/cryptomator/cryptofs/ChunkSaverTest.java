package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.hamcrest.MockitoHamcrest.argThat;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.concurrent.atomic.AtomicLong;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import com.google.common.base.Supplier;

public class ChunkSaverTest {

	private static final Integer HEADER_SIZE = 42;
	private static final Integer CLEARTEXT_CHUNK_SIZE = 13;
	private static final Integer CIPHERTEXT_CHUNK_SIZE = 37;

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private final FileChannel channel = mock(FileChannel.class);

	private final FileContentCryptor fileContentCryptor = mock(FileContentCryptor.class);
	private final FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private final Cryptor cryptor = mock(Cryptor.class);
	private final CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);
	private final AtomicLong size = new AtomicLong(0L);
	private final FileHeader header = mock(FileHeader.class);
	private final ExceptionsDuringWrite exceptionsDuringWrite = mock(ExceptionsDuringWrite.class);
	private final ChunkSaver inTest = new ChunkSaver(cryptor, channel, header, exceptionsDuringWrite, size, stats);

	@Before
	public void setup() {
		when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(fileContentCryptor.ciphertextChunkSize()).thenReturn(CIPHERTEXT_CHUNK_SIZE);
		when(fileContentCryptor.cleartextChunkSize()).thenReturn(CLEARTEXT_CHUNK_SIZE);
		when(fileHeaderCryptor.headerSize()).thenReturn(HEADER_SIZE);
	}

	@Test
	public void testChunkInsideFileIsWritten() throws IOException {
		long chunkIndex = 43L;
		long expectedPosition = HEADER_SIZE + chunkIndex * CIPHERTEXT_CHUNK_SIZE;
		ChunkData chunkData = ChunkData.emptyWithSize(CLEARTEXT_CHUNK_SIZE);
		Supplier<ByteBuffer> cleartext = () -> repeat(42).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer();
		Supplier<ByteBuffer> ciphertext = () -> repeat(50).times(CIPHERTEXT_CHUNK_SIZE).asByteBuffer();
		chunkData.copyData().from(cleartext.get());
		size.set((chunkIndex + 10L) * CLEARTEXT_CHUNK_SIZE);
		when(fileContentCryptor.encryptChunk(argThat(contains(cleartext.get())), eq(chunkIndex), eq(header))).thenReturn(ciphertext.get());

		inTest.save(chunkIndex, chunkData);

		verify(channel).write(argThat(contains(ciphertext.get())), eq(expectedPosition));
		verify(stats).addBytesEncrypted(Mockito.anyLong());
	}

	@Test
	public void testChunkContainingEndOfFileIsWrittenTillEndOfFile() throws IOException {
		long chunkIndex = 43L;
		long expectedPosition = HEADER_SIZE + chunkIndex * CIPHERTEXT_CHUNK_SIZE;
		ChunkData chunkData = ChunkData.emptyWithSize(CLEARTEXT_CHUNK_SIZE);
		Supplier<ByteBuffer> cleartext = () -> repeat(42).times(CLEARTEXT_CHUNK_SIZE - 10).asByteBuffer();
		Supplier<ByteBuffer> ciphertext = () -> repeat(50).times(CIPHERTEXT_CHUNK_SIZE - 10).asByteBuffer();
		chunkData.copyData().from(cleartext.get());
		size.set((chunkIndex + 10L) * CLEARTEXT_CHUNK_SIZE);
		when(fileContentCryptor.encryptChunk(argThat(contains(cleartext.get())), eq(chunkIndex), eq(header))).thenReturn(ciphertext.get());

		inTest.save(chunkIndex, chunkData);

		verify(channel).write(argThat(contains(ciphertext.get())), eq(expectedPosition));
		verify(stats).addBytesEncrypted(Mockito.anyLong());
	}

	@Test
	public void testChunkBeyondSizeIsNotWritten() {
		Long chunkIndex = 43L;
		ChunkData irrelevant = null;
		size.set(0);

		inTest.save(chunkIndex, irrelevant);

		verifyZeroInteractions(channel);
		verifyZeroInteractions(stats);
	}

	@Test
	public void testChunkThatWasNotWrittenIsNotWritten() {
		Long chunkIndex = 43L;
		ChunkData chunkData = ChunkData.emptyWithSize(CLEARTEXT_CHUNK_SIZE);
		size.set((chunkIndex + 10L) * CLEARTEXT_CHUNK_SIZE);

		inTest.save(chunkIndex, chunkData);

		verifyZeroInteractions(channel);
		verifyZeroInteractions(stats);
	}

	@Test
	public void testIOExceptionsDuringWriteAreAddedToExceptionsDuringWrite() throws IOException {
		IOException ioException = new IOException();
		long chunkIndex = 43L;
		long expectedPosition = HEADER_SIZE + chunkIndex * CIPHERTEXT_CHUNK_SIZE;
		ChunkData chunkData = ChunkData.emptyWithSize(CLEARTEXT_CHUNK_SIZE);
		Supplier<ByteBuffer> cleartext = () -> repeat(42).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer();
		Supplier<ByteBuffer> ciphertext = () -> repeat(50).times(CIPHERTEXT_CHUNK_SIZE).asByteBuffer();
		chunkData.copyData().from(cleartext.get());
		size.set((chunkIndex + 10L) * CLEARTEXT_CHUNK_SIZE);
		when(fileContentCryptor.encryptChunk(argThat(contains(cleartext.get())), eq(chunkIndex), eq(header))).thenReturn(ciphertext.get());
		when(channel.write(argThat(contains(ciphertext.get())), eq(expectedPosition))).thenThrow(ioException);

		inTest.save(chunkIndex, chunkData);

		verify(exceptionsDuringWrite).add(ioException);
	}

}
