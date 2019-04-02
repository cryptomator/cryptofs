package org.cryptomator.cryptofs.fh;

import com.google.common.base.Supplier;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;

import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.hamcrest.MockitoHamcrest.argThat;

public class ChunkSaverTest {

	private static final Integer HEADER_SIZE = 42;
	private static final Integer CLEARTEXT_CHUNK_SIZE = 13;
	private static final Integer CIPHERTEXT_CHUNK_SIZE = 37;

	private final ChunkIO chunkIO = mock(ChunkIO.class);
	private final FileContentCryptor fileContentCryptor = mock(FileContentCryptor.class);
	private final FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private final Cryptor cryptor = mock(Cryptor.class);
	private final CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);
	private final FileHeader header = mock(FileHeader.class);
	private final FileHeaderHandler headerHandler = mock(FileHeaderHandler.class);
	private final ExceptionsDuringWrite exceptionsDuringWrite = mock(ExceptionsDuringWrite.class);
	private final ChunkSaver inTest = new ChunkSaver(cryptor, chunkIO, headerHandler, exceptionsDuringWrite, stats);

	@BeforeEach
	public void setup() throws IOException {
		when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(headerHandler.get()).thenReturn(header);
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
		when(fileContentCryptor.encryptChunk(argThat(contains(cleartext.get())), eq(chunkIndex), eq(header))).thenReturn(ciphertext.get());

		inTest.save(chunkIndex, chunkData);

		verify(chunkIO).write(argThat(contains(ciphertext.get())), eq(expectedPosition));
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
		when(fileContentCryptor.encryptChunk(argThat(contains(cleartext.get())), eq(chunkIndex), eq(header))).thenReturn(ciphertext.get());

		inTest.save(chunkIndex, chunkData);

		verify(chunkIO).write(argThat(contains(ciphertext.get())), eq(expectedPosition));
		verify(stats).addBytesEncrypted(Mockito.anyLong());
	}

	@Test
	public void testChunkThatWasNotWrittenIsNotWritten() throws IOException {
		Long chunkIndex = 43L;
		ChunkData chunkData = ChunkData.emptyWithSize(CLEARTEXT_CHUNK_SIZE);

		inTest.save(chunkIndex, chunkData);

		verifyZeroInteractions(chunkIO);
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
		when(fileContentCryptor.encryptChunk(argThat(contains(cleartext.get())), eq(chunkIndex), eq(header))).thenReturn(ciphertext.get());
		when(chunkIO.write(argThat(contains(ciphertext.get())), eq(expectedPosition))).thenThrow(ioException);

		inTest.save(chunkIndex, chunkData);

		verify(exceptionsDuringWrite).add(ioException);
	}

}
