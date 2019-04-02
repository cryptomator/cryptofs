package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.function.Supplier;

import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.hasAtLeastRemaining;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.eq;
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
	private final FileHeaderHandler headerLoader = mock(FileHeaderHandler.class);
	private final ChunkLoader inTest = new ChunkLoader(cryptor, chunkIO, headerLoader, stats);

	@BeforeEach
	public void setup() throws IOException {
		when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(headerLoader.get()).thenReturn(header);
		when(fileContentCryptor.ciphertextChunkSize()).thenReturn(CIPHERTEXT_CHUNK_SIZE);
		when(fileContentCryptor.cleartextChunkSize()).thenReturn(CLEARTEXT_CHUNK_SIZE);
		when(fileHeaderCryptor.headerSize()).thenReturn(HEADER_SIZE);
	}

	@Test
	public void testChunkLoaderReturnsEmptyDataOfChunkAfterEndOfFile() throws IOException {
		long chunkIndex = 482L;
		long chunkOffset = chunkIndex * CIPHERTEXT_CHUNK_SIZE + HEADER_SIZE;
		when(chunkIO.read(argThat(hasAtLeastRemaining(CIPHERTEXT_CHUNK_SIZE)), eq(chunkOffset))).thenReturn(-1);

		ChunkData data = inTest.load(chunkIndex);

		verify(stats).addChunkCacheMiss();
		assertThat(data.asReadOnlyBuffer(), contains(ByteBuffer.allocate(0)));
		data.copyData().from(repeat(9).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer());
		assertThat(data.asReadOnlyBuffer(), contains(repeat(9).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer())); // asserts that data has at least CLEARTEXT_CHUNK_SIZE capacity
	}

	@Test
	public void testChunkLoaderReturnsDecryptedDataOfChunkInsideFile() throws IOException {
		long chunkIndex = 482L;
		long chunkOffset = chunkIndex * CIPHERTEXT_CHUNK_SIZE + HEADER_SIZE;
		Supplier<ByteBuffer> decryptedData = () -> repeat(9).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer();
		when(chunkIO.read(argThat(hasAtLeastRemaining(CIPHERTEXT_CHUNK_SIZE)), eq(chunkOffset))).then(fillBufferWith((byte) 3, CIPHERTEXT_CHUNK_SIZE));
		when(fileContentCryptor.decryptChunk( //
				argThat(contains(repeat(3).times(CIPHERTEXT_CHUNK_SIZE).asByteBuffer())), //
				eq(chunkIndex), eq(header), eq(true)) //
		).thenReturn(decryptedData.get());

		ChunkData data = inTest.load(chunkIndex);

		verify(stats).addChunkCacheMiss();
		verify(stats).addBytesDecrypted(data.asReadOnlyBuffer().remaining());
		assertThat(data.asReadOnlyBuffer(), contains(decryptedData.get()));
	}

	@Test
	public void testChunkLoaderReturnsDecrytedDataOfChunkContainingEndOfFile() throws IOException {
		long chunkIndex = 482L;
		long chunkOffset = chunkIndex * CIPHERTEXT_CHUNK_SIZE + HEADER_SIZE;
		Supplier<ByteBuffer> decryptedData = () -> repeat(9).times(CLEARTEXT_CHUNK_SIZE - 3).asByteBuffer();
		when(chunkIO.read(argThat(hasAtLeastRemaining(CIPHERTEXT_CHUNK_SIZE)), eq(chunkOffset))).then(fillBufferWith((byte) 3, CIPHERTEXT_CHUNK_SIZE - 10));
		when(fileContentCryptor.decryptChunk( //
				argThat(contains(repeat(3).times(CIPHERTEXT_CHUNK_SIZE - 10).asByteBuffer())), //
				eq(chunkIndex), eq(header), eq(true)) //
		).thenReturn(decryptedData.get());

		ChunkData data = inTest.load(chunkIndex);

		verify(stats).addChunkCacheMiss();
		verify(stats).addBytesDecrypted(data.asReadOnlyBuffer().remaining());
		assertThat(data.asReadOnlyBuffer(), contains(decryptedData.get()));
		data.copyData().from(repeat(9).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer());
		assertThat(data.asReadOnlyBuffer(), contains(repeat(9).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer())); // asserts that data has at least CLEARTEXT_CHUNK_SIZE capacity
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
