package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptofs.matchers.ByteBufferMatcher;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.function.Supplier;

import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.hasAtLeastRemaining;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.hamcrest.MockitoHamcrest.argThat;

public class ChunkLoaderTest {

	private static final Integer HEADER_SIZE = 42;
	private static final Integer CLEARTEXT_CHUNK_SIZE = 13;
	private static final Integer CIPHERTEXT_CHUNK_SIZE = 37;

	private final ChunkIO chunkIO = mock(ChunkIO.class);
	private final FileContentCryptor fileContentCryptor = mock(FileContentCryptor.class);
	private final FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private final Cryptor cryptor = mock(Cryptor.class);
	private final CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);
	private final FileHeader header = mock(FileHeader.class);
	private final FileHeaderHolder headerHolder = mock(FileHeaderHolder.class);
	private final BufferPool bufferPool = mock(BufferPool.class);
	private final ChunkLoader inTest = new ChunkLoader(cryptor, chunkIO, headerHolder, stats, bufferPool);

	@BeforeEach
	public void setup() throws IOException {
		when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(headerHolder.get()).thenReturn(header);
		when(fileContentCryptor.ciphertextChunkSize()).thenReturn(CIPHERTEXT_CHUNK_SIZE);
		when(fileContentCryptor.cleartextChunkSize()).thenReturn(CLEARTEXT_CHUNK_SIZE);
		when(fileHeaderCryptor.headerSize()).thenReturn(HEADER_SIZE);
		when(bufferPool.getCiphertextBuffer()).thenAnswer(invocation -> ByteBuffer.allocate(CIPHERTEXT_CHUNK_SIZE));
		when(bufferPool.getCleartextBuffer()).thenAnswer(invocation -> ByteBuffer.allocate(CLEARTEXT_CHUNK_SIZE));
	}

	@Test
	@DisplayName("load() returns empty chunk when hitting EOF")
	public void testLoadReturnsEmptyChunkAfterEOF() throws IOException, AuthenticationFailedException {
		long chunkIndex = 482L;
		long chunkOffset = chunkIndex * CIPHERTEXT_CHUNK_SIZE + HEADER_SIZE;
		when(chunkIO.read(argThat(hasAtLeastRemaining(CIPHERTEXT_CHUNK_SIZE)), eq(chunkOffset))).thenReturn(-1);

		var data = inTest.load(chunkIndex);

		verify(stats).addChunkCacheMiss();
		verify(bufferPool).recycle(argThat(ByteBufferMatcher.hasCapacity(CIPHERTEXT_CHUNK_SIZE)));
		Assertions.assertEquals(0, data.remaining());
		Assertions.assertEquals(CLEARTEXT_CHUNK_SIZE, data.capacity());
	}

	@Test
	@DisplayName("load() returns full chunk when in middle of file")
	public void testLoadReturnsDecryptedDataInsideFile() throws IOException, AuthenticationFailedException {
		long chunkIndex = 482L;
		long chunkOffset = chunkIndex * CIPHERTEXT_CHUNK_SIZE + HEADER_SIZE;
		Supplier<ByteBuffer> decryptedData = () -> repeat(9).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer();
		when(chunkIO.read(argThat(hasAtLeastRemaining(CIPHERTEXT_CHUNK_SIZE)), eq(chunkOffset))).then(fillBufferWith((byte) 3, CIPHERTEXT_CHUNK_SIZE));
		doAnswer(invocation -> {
			ByteBuffer cleartextBuf = invocation.getArgument(1);
			cleartextBuf.put(decryptedData.get());
			return null;
		}).when(fileContentCryptor).decryptChunk(
				argThat(contains(repeat(3).times(CIPHERTEXT_CHUNK_SIZE).asByteBuffer())), //
				Mockito.any(), eq(chunkIndex), eq(header), eq(true) //
		);

		var data = inTest.load(chunkIndex);

		verify(stats).addChunkCacheMiss();
		verify(stats).addBytesDecrypted(data.remaining());
		verify(bufferPool).recycle(argThat(ByteBufferMatcher.hasCapacity(CIPHERTEXT_CHUNK_SIZE)));
		assertThat(data, contains(decryptedData.get()));
		Assertions.assertEquals(CLEARTEXT_CHUNK_SIZE, data.remaining());
		Assertions.assertEquals(CLEARTEXT_CHUNK_SIZE, data.capacity());
	}

	@Test
	@DisplayName("load() returns partial chunk near EOF")
	public void testLoadReturnsDecrytedDataNearEOF() throws IOException, AuthenticationFailedException {
		long chunkIndex = 482L;
		long chunkOffset = chunkIndex * CIPHERTEXT_CHUNK_SIZE + HEADER_SIZE;
		Supplier<ByteBuffer> decryptedData = () -> repeat(9).times(CLEARTEXT_CHUNK_SIZE - 3).asByteBuffer();
		when(chunkIO.read(argThat(hasAtLeastRemaining(CIPHERTEXT_CHUNK_SIZE)), eq(chunkOffset))).then(fillBufferWith((byte) 3, CIPHERTEXT_CHUNK_SIZE - 10));
		doAnswer(invocation -> {
			ByteBuffer cleartextBuf = invocation.getArgument(1);
			cleartextBuf.put(decryptedData.get());
			return null;
		}).when(fileContentCryptor).decryptChunk(
				argThat(contains(repeat(3).times(CIPHERTEXT_CHUNK_SIZE - 10).asByteBuffer())), //
				any(ByteBuffer.class), eq(chunkIndex), eq(header), eq(true) //
		);

		var data = inTest.load(chunkIndex);

		verify(stats).addChunkCacheMiss();
		verify(stats).addBytesDecrypted(data.remaining());
		verify(bufferPool).recycle(argThat(ByteBufferMatcher.hasCapacity(CIPHERTEXT_CHUNK_SIZE)));
		assertThat(data, contains(decryptedData.get()));
		Assertions.assertEquals(CLEARTEXT_CHUNK_SIZE - 3, data.remaining());
		Assertions.assertEquals(CLEARTEXT_CHUNK_SIZE, data.capacity());
	}

	private Answer<Integer> fillBufferWith(byte value, int amount) {
		return invocation -> {
			ByteBuffer buffer = invocation.getArgument(0);
			for (int i = 0; i < amount; i++) {
				buffer.put(value);
			}
			return amount;
		};
	}

}
