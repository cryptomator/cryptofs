package org.cryptomator.cryptofs.fh;

import com.github.benmanes.caffeine.cache.RemovalCause;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class ChunkCacheTest {

	private final ChunkLoader chunkLoader = mock(ChunkLoader.class);
	private final ChunkSaver chunkSaver = mock(ChunkSaver.class);
	private final CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);
	private final BufferPool bufferPool = mock(BufferPool.class);
	private final ExceptionsDuringWrite exceptionsDuringWrite = mock(ExceptionsDuringWrite.class);
	private final ChunkCache inTest = new ChunkCache(chunkLoader, chunkSaver, stats, bufferPool, exceptionsDuringWrite);

	@Test
	@DisplayName("getChunk returns chunk with access count == 1")
	public void testGetIncreasesAccessCounter() throws IOException {
		long index = 42L;
		var data = ByteBuffer.allocate(0);
		when(chunkLoader.load(index)).thenReturn(data);

		var result = inTest.getChunk(index);

		Assertions.assertEquals(1, result.currentAccesses().get());
	}

	@Test
	@DisplayName("getChunk invokes chunkLoader.load() on cache miss")
	public void testGetInvokesLoaderIfEntryNotInCache() throws IOException, AuthenticationFailedException {
		long index = 42L;
		var data = ByteBuffer.allocate(0);
		when(chunkLoader.load(index)).thenReturn(data);

		inTest.getChunk(index);

		verify(chunkLoader).load(index);
		verify(stats).addChunkCacheAccess();
	}

	@Test
	@DisplayName("getChunk does not invoke chunkLoader.load() on cache hit due to getting chunk twice")
	public void testGetDoesNotInvokeLoaderIfEntryInCacheFromPreviousGet() throws IOException, AuthenticationFailedException {
		long index = 42L;
		var data = ByteBuffer.allocate(0);
		when(chunkLoader.load(index)).thenReturn(data);

		var chunk = inTest.getChunk(index);
		var sameChunk = inTest.getChunk(index);

		Assertions.assertSame(chunk, sameChunk);
		verify(chunkLoader, Mockito.times(1)).load(index);
		verify(stats, Mockito.times(2)).addChunkCacheAccess();
		verify(stats, Mockito.times(1)).addChunkCacheMiss();
	}

	@Test
	@DisplayName("getChunk does not invoke chunkLoader.load() on cache hit due to getting after putting")
	public void testGetDoesNotInvokeLoaderIfEntryInCacheFromPreviousSet() throws IOException {
		long index = 42L;
		var data = ByteBuffer.allocate(0);
		var chunk = inTest.putChunk(index, data);

		Assertions.assertSame(chunk, inTest.getChunk(index));
		verify(stats).addChunkCacheAccess();
	}

	@Test
	@DisplayName("putChunk returns a dirty chunk")
	public void testPutChunkReturnsDirtyChunk() {
		long index = 42L;
		var data = ByteBuffer.allocate(0);
		var chunk = inTest.putChunk(index, data);

		Assertions.assertTrue(chunk.isDirty());
	}

	@RepeatedTest(100)
	@DisplayName("getChunk() triggers cache eviction if stale cache contains MAX_CACHED_CLEARTEXT_CHUNKS entries")
	public void testGetInvokesSaverIfMaxEntriesInCacheAreReachedAndAnEntryNotInCacheIsRequested() throws IOException, AuthenticationFailedException {
		long firstIndex = 42L;
		long indexNotInCache = 40L;
		for (long i = firstIndex; i < firstIndex + ChunkCache.MAX_CACHED_CLEARTEXT_CHUNKS; i++) {
			inTest.putChunk(i, ByteBuffer.allocate(0)).close();
		}
		var cdl = new CountDownLatch(1);
		Mockito.doReturn(ByteBuffer.allocate(0)).when(chunkLoader).load(indexNotInCache);
		Mockito.doAnswer(invocation -> {
			cdl.countDown();
			return null;
		}).when(chunkSaver).save(Mockito.anyLong(), Mockito.any());

		inTest.getChunk(indexNotInCache).close();

		Assertions.assertTimeoutPreemptively(Duration.ofMillis(100), () -> {
			cdl.await();
		});
		verify(stats).addChunkCacheAccess();
		verify(chunkSaver).save(Mockito.eq(firstIndex), Mockito.any());
		verify(bufferPool).recycle(Mockito.any());
		verifyNoMoreInteractions(chunkSaver);
	}

	@Test
	@DisplayName("getChunk() propagates AuthenticationFailedException from loader")
	public void testGetRethrowsAuthenticationFailedExceptionFromLoader() throws IOException, AuthenticationFailedException {
		AuthenticationFailedException authenticationFailedException = new AuthenticationFailedException("Foo");
		when(chunkLoader.load(42L)).thenThrow(authenticationFailedException);

		IOException e = Assertions.assertThrows(IOException.class, () -> {
			inTest.getChunk(42L);
		});
		Assertions.assertSame(authenticationFailedException, e.getCause());
	}

	@Test
	@DisplayName("getChunk() rethrows RuntimeException from loader")
	public void testGetThrowsUncheckedExceptionFromLoader() throws IOException, AuthenticationFailedException {
		RuntimeException uncheckedException = new RuntimeException();
		when(chunkLoader.load(42L)).thenThrow(uncheckedException);

		Assertions.assertThrows(RuntimeException.class, () -> {
			inTest.getChunk(42);
		});
	}

	@Test
	@DisplayName("getChunk() propagates IOException from loader")
	public void testGetRethrowsIOExceptionFromLoader() throws IOException, AuthenticationFailedException {
		when(chunkLoader.load(42L)).thenThrow(new IOException());

		Assertions.assertThrows(IOException.class, () -> {
			inTest.getChunk(42L);
		});
	}

	@Test
	@DisplayName("flush() saves all active chunks")
	public void testFlushInvokesSaverForAllActiveChunks() throws IOException, AuthenticationFailedException {
		long index = 42L;
		long index2 = 43L;

		try (var chunk1 = inTest.putChunk(index, ByteBuffer.allocate(0)); var chunk2 = inTest.putChunk(index2, ByteBuffer.allocate(0))) {
			inTest.flush();

			verify(chunkSaver).save(Mockito.eq(index), Mockito.any());
			verify(chunkSaver).save(Mockito.eq(index2), Mockito.any());
		}
	}

	@Test
	@DisplayName("flush() saves all stale chunks")
	public void testFlushInvokesSaverForAllStaleChunks() throws IOException, AuthenticationFailedException {
		long index = 42L;
		long index2 = 43L;

		try (var chunk1 = inTest.putChunk(index, ByteBuffer.allocate(0)); var chunk2 = inTest.putChunk(index2, ByteBuffer.allocate(0))) {
			// no-op
		}

		inTest.flush();

		verify(chunkSaver).save(Mockito.eq(index), Mockito.any());
		verify(chunkSaver).save(Mockito.eq(index2), Mockito.any());
	}


	@Test
	public void testIOExceptionsDuringWriteAreAddedToExceptionsDuringWrite() throws IOException {
		IOException ioException = new IOException();
		Chunk chunk = new Chunk(ByteBuffer.allocate(0), true, () -> {});
		Mockito.doThrow(ioException).when(chunkSaver).save(42L, chunk);

		inTest.evictStaleChunk(42L, chunk, RemovalCause.EXPIRED);

		verify(exceptionsDuringWrite).add(ioException);
	}

}
