package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class ChunkCacheTest {

	private final ChunkLoader chunkLoader = mock(ChunkLoader.class);
	private final ChunkSaver chunkSaver = mock(ChunkSaver.class);
	private final CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);
	private final BufferPool bufferPool = mock(BufferPool.class);
	private final ChunkCache inTest = new ChunkCache(chunkLoader, chunkSaver, stats, bufferPool);

	@Test
	public void testGetIncreasesAccessCounter() throws IOException {
		long index = 42L;
		Chunk chunk = mock(Chunk.class);
		AtomicInteger cnt = new AtomicInteger(0);
		when(chunk.currentAccesses()).thenReturn(cnt);
		when(chunkLoader.load(index)).thenReturn(chunk);

		var result = inTest.acquireChunk(index);

		Assertions.assertSame(chunk, result);
		Assertions.assertEquals(1, cnt.get());
	}

	@Test
	public void testGetInvokesLoaderIfEntryNotInCache() throws IOException, AuthenticationFailedException {
		long index = 42L;
		Chunk chunk = mock(Chunk.class);
		when(chunk.currentAccesses()).thenReturn(new AtomicInteger());
		when(chunkLoader.load(index)).thenReturn(chunk);

		Assertions.assertSame(chunk, inTest.acquireChunk(index));
		verify(stats).addChunkCacheAccess();
	}

	@Test
	public void testGetDoesNotInvokeLoaderIfEntryInCacheFromPreviousGet() throws IOException, AuthenticationFailedException {
		long index = 42L;
		Chunk chunk = mock(Chunk.class);
		when(chunk.currentAccesses()).thenReturn(new AtomicInteger());
		when(chunkLoader.load(index)).thenReturn(chunk);
		inTest.acquireChunk(index);

		Assertions.assertSame(chunk, inTest.acquireChunk(index));
		verify(stats, Mockito.times(2)).addChunkCacheAccess();
		verify(chunkLoader).load(index);
	}

	@Test
	public void testGetDoesNotInvokeLoaderIfEntryInCacheFromPreviousSet() throws IOException {
		long index = 42L;
		Chunk chunk = mock(Chunk.class);
		when(chunk.currentAccesses()).thenReturn(new AtomicInteger());
		inTest.set(index, chunk);

		Assertions.assertSame(chunk, inTest.acquireChunk(index));
		verify(stats).addChunkCacheAccess();
	}

	@Test
	public void testGetDoesNotRecycleBuffer

	@Test
	public void testGetInvokesSaverIfMaxEntriesInCacheAreReachedAndAnEntryNotInCacheIsRequested() throws IOException, AuthenticationFailedException {
		long firstIndex = 42L;
		long indexNotInCache = 40L;
		Chunk chunk = mock(Chunk.class);
		when(chunk.currentAccesses()).thenReturn(new AtomicInteger());
		inTest.set(firstIndex, chunk);
		for (int i = 1; i < ChunkCache.MAX_CACHED_CLEARTEXT_CHUNKS; i++) {
			inTest.set(firstIndex + i, mock(Chunk.class));
		}
		Chunk notIndexedChunk = mock(Chunk.class);
		when(notIndexedChunk.currentAccesses()).thenReturn(new AtomicInteger());
		when(chunkLoader.load(indexNotInCache)).thenReturn(notIndexedChunk);

		inTest.acquireChunk(indexNotInCache);

		verify(stats).addChunkCacheAccess();
		verify(chunkSaver).save(firstIndex, chunk);
		verify(bufferPool).recycle(chunk.data());
		verifyNoMoreInteractions(chunkSaver);
	}

	@Test
	public void testGetInvokesSaverIfMaxEntriesInCacheAreReachedAndAnEntryNotInCacheIsSet() throws IOException {
		long firstIndex = 42L;
		long indexNotInCache = 40L;
		Chunk chunk = mock(Chunk.class);
		when(chunk.currentAccesses()).thenReturn(new AtomicInteger());
		inTest.set(firstIndex, chunk);
		for (int i = 1; i < ChunkCache.MAX_CACHED_CLEARTEXT_CHUNKS; i++) {
			inTest.set(firstIndex + i, mock(Chunk.class));
		}

		inTest.set(indexNotInCache, mock(Chunk.class));

		verify(chunkSaver).save(firstIndex, chunk);
		verify(bufferPool).recycle(chunk.data());
		verifyNoMoreInteractions(chunkSaver);
	}

	@Test
	public void testGetInvokesSaverIfMaxEntriesInCacheAreReachedAndAnEntryInCacheIsSet() throws IOException {
		// TODO markuskreusch: this behaviour isn't actually needed, maybe we can somehow prevent saving in such situations?
		long firstIndex = 42L;
		Chunk chunk = mock(Chunk.class);
		when(chunk.currentAccesses()).thenReturn(new AtomicInteger());
		inTest.set(firstIndex, chunk);
		for (int i = 1; i < ChunkCache.MAX_CACHED_CLEARTEXT_CHUNKS; i++) {
			inTest.set(firstIndex + i, mock(Chunk.class));
		}

		inTest.set(firstIndex, mock(Chunk.class));

		verify(chunkSaver).save(firstIndex, chunk);
		verify(bufferPool).recycle(chunk.data());
		verifyNoMoreInteractions(chunkSaver);
	}

	@Test
	public void testGetRethrowsAuthenticationFailedExceptionFromLoader() throws IOException, AuthenticationFailedException {
		long index = 42L;
		AuthenticationFailedException authenticationFailedException = new AuthenticationFailedException("Foo");
		when(chunkLoader.load(index)).thenThrow(authenticationFailedException);

		IOException e = Assertions.assertThrows(IOException.class, () -> {
			inTest.acquireChunk(index);
		});
		Assertions.assertSame(authenticationFailedException, e.getCause());
	}

	@Test
	public void testGetThrowsUncheckedExceptionFromLoader() throws IOException, AuthenticationFailedException {
		long index = 42L;
		RuntimeException uncheckedException = new RuntimeException();
		when(chunkLoader.load(index)).thenThrow(uncheckedException);

		RuntimeException e = Assertions.assertThrows(RuntimeException.class, () -> {
			inTest.acquireChunk(index);
		});
		Assertions.assertSame(uncheckedException, e.getCause());
	}

	@Test
	public void testInvalidateAllInvokesSaverForAllEntriesInCache() throws IOException, AuthenticationFailedException {
		long index = 42L;
		long index2 = 43L;
		Chunk chunk1 = mock(Chunk.class);
		Chunk chunk2 = mock(Chunk.class);
		when(chunk1.data()).thenReturn(ByteBuffer.allocate(42));
		when(chunk2.data()).thenReturn(ByteBuffer.allocate(23));
		when(chunk1.currentAccesses()).thenReturn(new AtomicInteger());
		when(chunk2.currentAccesses()).thenReturn(new AtomicInteger());
		when(chunkLoader.load(index)).thenReturn(chunk1);
		inTest.acquireChunk(index);
		inTest.set(index2, chunk2);

		inTest.invalidateAll();

		verify(chunkSaver).save(index, chunk1);
		verify(bufferPool).recycle(chunk1.data());
		verify(chunkSaver).save(index2, chunk2);
		verify(bufferPool).recycle(chunk2.data());
	}

	@Test
	public void testGetRethrowsIOExceptionFromLoader() throws IOException, AuthenticationFailedException {
		long index = 42L;
		IOException ioException = new IOException();
		when(chunkLoader.load(index)).thenThrow(ioException);

		IOException e = Assertions.assertThrows(IOException.class, () -> {
			inTest.acquireChunk(index);
		});
		Assertions.assertSame(ioException, e);
	}

}
