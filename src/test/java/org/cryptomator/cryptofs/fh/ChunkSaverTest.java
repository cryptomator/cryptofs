package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptofs.matchers.ByteBufferMatcher;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
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
	private final FileHeaderHolder headerHolder = mock(FileHeaderHolder.class);
	private final BufferPool bufferPool = mock(BufferPool.class);
	private final ChunkSaver inTest = new ChunkSaver(cryptor, chunkIO, headerHolder, stats, bufferPool);
	private final List<ByteBuffer> writtenChunks = new ArrayList<>();
	private int bytesAccepted;

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
		// a real FileChannel consumes the written bytes and returns how many it wrote
		when(chunkIO.write(Mockito.any(), Mockito.anyLong())).thenAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			ByteBuffer copy = ByteBuffer.allocate(buf.remaining());
			copy.put(buf.duplicate()).flip();
			writtenChunks.add(copy);
			int written = buf.remaining();
			buf.position(buf.limit());
			return written;
		});
	}

	@Test
	public void testSuccessfullWrittenChunkIsNonDirty() throws IOException {
		long chunkIndex = 43L;
		Supplier<ByteBuffer> cleartext = () -> repeat(42).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer();
		Chunk chunk = new Chunk(cleartext.get(), true, () -> {});
		doNothing().when(fileContentCryptor).encryptChunk(argThat(contains(cleartext.get())), Mockito.any(), eq(chunkIndex), eq(header));

		inTest.save(chunkIndex, chunk);

		Assertions.assertFalse(chunk.isDirty());
	}

	@Test
	public void testChunkInsideFileIsWritten() throws IOException {
		long chunkIndex = 43L;
		long expectedPosition = HEADER_SIZE + chunkIndex * CIPHERTEXT_CHUNK_SIZE;
		Supplier<ByteBuffer> cleartext = () -> repeat(42).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer();
		Supplier<ByteBuffer> ciphertext = () -> repeat(50).times(CIPHERTEXT_CHUNK_SIZE).asByteBuffer();
		Chunk chunk = new Chunk(cleartext.get(), true, () -> {});
		doAnswer(invocation -> {
			ByteBuffer ciphertextBuf = invocation.getArgument(1);
			ciphertextBuf.put(ciphertext.get());
			return null;
		}).when(fileContentCryptor).encryptChunk(argThat(contains(cleartext.get())), Mockito.any(), eq(chunkIndex), eq(header));

		inTest.save(chunkIndex, chunk);

		verify(chunkIO).write(Mockito.any(), eq(expectedPosition));
		Assertions.assertTrue(writtenChunks.stream().anyMatch(contains(ciphertext.get())::matches), "expected ciphertext to be written");
		verify(stats).addBytesEncrypted(Mockito.anyLong());
		verify(bufferPool).recycle(argThat(ByteBufferMatcher.hasCapacity(CIPHERTEXT_CHUNK_SIZE)));
	}

	@Test
	public void testChunkContainingEndOfFileIsWrittenTillEndOfFile() throws IOException {
		long chunkIndex = 43L;
		long expectedPosition = HEADER_SIZE + chunkIndex * CIPHERTEXT_CHUNK_SIZE;
		Supplier<ByteBuffer> cleartext = () -> repeat(42).times(CLEARTEXT_CHUNK_SIZE - 10).asByteBuffer();
		Supplier<ByteBuffer> ciphertext = () -> repeat(50).times(CIPHERTEXT_CHUNK_SIZE - 10).asByteBuffer();
		Chunk chunk = new Chunk(cleartext.get(), true, () -> {});
		doAnswer(invocation -> {
			ByteBuffer ciphertextBuf = invocation.getArgument(1);
			ciphertextBuf.put(ciphertext.get());
			return null;
		}).when(fileContentCryptor).encryptChunk(argThat(contains(cleartext.get())), Mockito.any(), eq(chunkIndex), eq(header));

		inTest.save(chunkIndex, chunk);

		verify(chunkIO).write(Mockito.any(), eq(expectedPosition));
		Assertions.assertTrue(writtenChunks.stream().anyMatch(contains(ciphertext.get())::matches), "expected ciphertext to be written");
		verify(stats).addBytesEncrypted(Mockito.anyLong());
		verify(bufferPool).recycle(argThat(ByteBufferMatcher.hasCapacity(CIPHERTEXT_CHUNK_SIZE)));
	}

	@Test
	public void testCleartextBufferHandedToCryptorIsWritable() throws IOException {
		long chunkIndex = 43L;
		var cleartext = repeat(42).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer();
		var chunk = new Chunk(cleartext, true, () -> {});
		var seenByCryptor = new AtomicReference<ByteBuffer>();
		doAnswer(invocation -> {
			seenByCryptor.set(invocation.getArgument(0));
			return null;
		}).when(fileContentCryptor).encryptChunk(Mockito.any(), Mockito.any(), Mockito.eq(chunkIndex), Mockito.eq(header));

		inTest.save(chunkIndex, chunk);

		// a read-only buffer reports hasArray() == false, which disables the JCE heap fast path
		Assertions.assertFalse(seenByCryptor.get().isReadOnly());
	}

	@Test
	public void testShortWritesAreRetried() throws IOException {
		long chunkIndex = 43L;
		var cleartext = repeat(42).times(CLEARTEXT_CHUNK_SIZE).asByteBuffer();
		var ciphertext = repeat(50).times(CIPHERTEXT_CHUNK_SIZE).asByteBuffer();
		var chunk = new Chunk(cleartext, true, () -> {});
		doAnswer(invocation -> {
			ByteBuffer ciphertextBuf = invocation.getArgument(1);
			ciphertextBuf.put(ciphertext.duplicate());
			return null;
		}).when(fileContentCryptor).encryptChunk(Mockito.any(), Mockito.any(), Mockito.eq(chunkIndex), Mockito.eq(header));
		// a channel that accepts at most 10 bytes per call
		// doAnswer (not when(...).thenAnswer) so re-stubbing does not invoke the previous answer with null arguments
		doAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			int accepted = Math.min(10, buf.remaining());
			buf.position(buf.position() + accepted);
			bytesAccepted += accepted;
			return accepted;
		}).when(chunkIO).write(Mockito.any(), Mockito.anyLong());

		inTest.save(chunkIndex, chunk);

		Assertions.assertEquals(CIPHERTEXT_CHUNK_SIZE.intValue(), bytesAccepted);
		Assertions.assertFalse(chunk.isDirty());
	}

	@Test
	public void testChunkThatWasNotWrittenIsNotWritten() throws IOException {
		Long chunkIndex = 43L;
		Chunk chunk = new Chunk(ByteBuffer.allocate(CLEARTEXT_CHUNK_SIZE), false, () -> {});

		inTest.save(chunkIndex, chunk);

		verifyNoInteractions(chunkIO);
		verifyNoInteractions(stats);
		verifyNoInteractions(bufferPool);
	}

}
