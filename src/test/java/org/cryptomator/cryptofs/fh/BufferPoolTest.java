package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.nio.ByteBuffer;

public class BufferPoolTest {

	private static final int CLEARTEXT_CHUNK_SIZE = 100;
	private static final int CIPHERTEXT_CHUNK_SIZE = 150;

	private final Cryptor cryptor = Mockito.mock(Cryptor.class);
	private final FileContentCryptor fileContentCryptor = Mockito.mock(FileContentCryptor.class);
	private BufferPool bufferPool;

	@BeforeEach
	public void setup() {
		Mockito.doReturn(fileContentCryptor).when(cryptor).fileContentCryptor();
		Mockito.doReturn(CLEARTEXT_CHUNK_SIZE).when(fileContentCryptor).cleartextChunkSize();
		Mockito.doReturn(CIPHERTEXT_CHUNK_SIZE).when(fileContentCryptor).ciphertextChunkSize();
		bufferPool = new BufferPool(cryptor);
	}

	@Test
	@DisplayName("getCiphertextBuffer() with no cached item")
	public void testGetUncachedCiphertextBuffer() {
		try (var byteBufferClass = Mockito.mockStatic(ByteBuffer.class)) {
			byteBufferClass.when(() -> ByteBuffer.allocate(Mockito.anyInt())).thenCallRealMethod();
			var buf = bufferPool.getCiphertextBuffer();

			Assertions.assertEquals(CIPHERTEXT_CHUNK_SIZE, buf.capacity());
			byteBufferClass.verify(() -> ByteBuffer.allocate(CIPHERTEXT_CHUNK_SIZE));
		}
	}

	@Test
	@DisplayName("getCiphertextBuffer() after recycling ciphertext")
	public void testGetCachedCiphertextBuffer() {
		var buf0 = ByteBuffer.allocate(CIPHERTEXT_CHUNK_SIZE);
		bufferPool.recycle(buf0);
		buf0 = null;
		System.gc(); // seems to be reliable on Temurin 17 with @RepeatedTest(1000)

		var buf1 = ByteBuffer.allocate(CIPHERTEXT_CHUNK_SIZE);
		bufferPool.recycle(buf1);

		try (var byteBufferClass = Mockito.mockStatic(ByteBuffer.class)) {
			var buf2 = bufferPool.getCiphertextBuffer();

			Assertions.assertSame(buf1, buf2);
			Assertions.assertEquals(0, buf2.position(), "expected recycled buffer to be cleared");
			Assertions.assertEquals(buf2.capacity(), buf2.limit(), "expected recycled buffer to be cleared");
			byteBufferClass.verifyNoInteractions();
		}
	}

	@Test
	@DisplayName("getCleartextBuffer() with no cached item")
	public void testGetUncachedCleartextBuffer() {
		try (var byteBufferClass = Mockito.mockStatic(ByteBuffer.class)) {
			byteBufferClass.when(() -> ByteBuffer.allocate(Mockito.anyInt())).thenCallRealMethod();
			var buf = bufferPool.getCleartextBuffer();

			Assertions.assertEquals(CLEARTEXT_CHUNK_SIZE, buf.capacity());
			byteBufferClass.verify(() -> ByteBuffer.allocate(CLEARTEXT_CHUNK_SIZE));
		}
	}

	@Test
	@DisplayName("getCleartextBuffer() after recycling cleartext")
	public void testGetCachedCleartextBuffer() {
		var buf0 = ByteBuffer.allocate(CIPHERTEXT_CHUNK_SIZE);
		bufferPool.recycle(buf0);
		buf0 = null;
		System.gc(); // seems to be reliable on Temurin 17 with @RepeatedTest(1000)

		var buf1 = ByteBuffer.allocate(CLEARTEXT_CHUNK_SIZE);
		bufferPool.recycle(buf1);

		try (var byteBufferClass = Mockito.mockStatic(ByteBuffer.class)) {
			var buf2 = bufferPool.getCleartextBuffer();

			Assertions.assertSame(buf1, buf2);
			Assertions.assertEquals(0, buf2.position(), "expected recycled buffer to be cleared");
			Assertions.assertEquals(buf2.capacity(), buf2.limit(), "expected recycled buffer to be cleared");
			byteBufferClass.verifyNoInteractions();
		}
	}

	@DisplayName("recycle() accepts any size")
	@ParameterizedTest
	@ValueSource(ints = {CIPHERTEXT_CHUNK_SIZE, CLEARTEXT_CHUNK_SIZE, 42})
	public void testRecycle(int capacity) {
		var buf = ByteBuffer.allocate(capacity);

		Assertions.assertDoesNotThrow(() -> bufferPool.recycle(buf));
	}

}