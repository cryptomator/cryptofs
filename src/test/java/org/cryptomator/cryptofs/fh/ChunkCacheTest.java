package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;

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
	public void testGetInvokesLoaderIfEntryNotInCache() throws IOException, AuthenticationFailedException {
		long index = 42L;
		ChunkData data = mock(ChunkData.class);
		when(chunkLoader.load(index)).thenReturn(data);

		Assertions.assertSame(data, inTest.get(index));
		verify(stats).addChunkCacheAccess();
	}

	@Test
	public void testGetDoesNotInvokeLoaderIfEntryInCacheFromPreviousGet() throws IOException, AuthenticationFailedException {
		long index = 42L;
		ChunkData data = mock(ChunkData.class);
		when(chunkLoader.load(index)).thenReturn(data);
		inTest.get(index);

		Assertions.assertSame(data, inTest.get(index));
		verify(stats, Mockito.times(2)).addChunkCacheAccess();
		verify(chunkLoader).load(index);
	}

	@Test
	public void testGetDoesNotInvokeLoaderIfEntryInCacheFromPreviousSet() throws IOException {
		long index = 42L;
		ChunkData data = mock(ChunkData.class);
		inTest.set(index, data);

		Assertions.assertSame(data, inTest.get(index));
		verify(stats).addChunkCacheAccess();
	}

	@Test
	public void testGetInvokesSaverIfMaxEntriesInCacheAreReachedAndAnEntryNotInCacheIsRequested() throws IOException, AuthenticationFailedException {
		long firstIndex = 42L;
		long indexNotInCache = 40L;
		ChunkData firstData = mock(ChunkData.class);
		inTest.set(firstIndex, firstData);
		for (int i = 1; i < ChunkCache.MAX_CACHED_CLEARTEXT_CHUNKS; i++) {
			inTest.set(firstIndex + i, mock(ChunkData.class));
		}
		when(chunkLoader.load(indexNotInCache)).thenReturn(mock(ChunkData.class));

		inTest.get(indexNotInCache);

		verify(stats).addChunkCacheAccess();
		verify(chunkSaver).save(firstIndex, firstData);
		verify(bufferPool).recycle(firstData.data());
		verifyNoMoreInteractions(chunkSaver);
	}

	@Test
	public void testGetInvokesSaverIfMaxEntriesInCacheAreReachedAndAnEntryNotInCacheIsSet() throws IOException {
		long firstIndex = 42L;
		long indexNotInCache = 40L;
		ChunkData firstData = mock(ChunkData.class);
		inTest.set(firstIndex, firstData);
		for (int i = 1; i < ChunkCache.MAX_CACHED_CLEARTEXT_CHUNKS; i++) {
			inTest.set(firstIndex + i, mock(ChunkData.class));
		}

		inTest.set(indexNotInCache, mock(ChunkData.class));

		verify(chunkSaver).save(firstIndex, firstData);
		verify(bufferPool).recycle(firstData.data());
		verifyNoMoreInteractions(chunkSaver);
	}

	@Test
	public void testGetInvokesSaverIfMaxEntriesInCacheAreReachedAndAnEntryInCacheIsSet() throws IOException {
		// TODO markuskreusch: this behaviour isn't actually needed, maybe we can somehow prevent saving in such situations?
		long firstIndex = 42L;
		ChunkData firstData = mock(ChunkData.class);
		inTest.set(firstIndex, firstData);
		for (int i = 1; i < ChunkCache.MAX_CACHED_CLEARTEXT_CHUNKS; i++) {
			inTest.set(firstIndex + i, mock(ChunkData.class));
		}

		inTest.set(firstIndex, mock(ChunkData.class));

		verify(chunkSaver).save(firstIndex, firstData);
		verify(bufferPool).recycle(firstData.data());
		verifyNoMoreInteractions(chunkSaver);
	}

	@Test
	public void testGetRethrowsAuthenticationFailedExceptionFromLoader() throws IOException, AuthenticationFailedException {
		long index = 42L;
		AuthenticationFailedException authenticationFailedException = new AuthenticationFailedException("Foo");
		when(chunkLoader.load(index)).thenThrow(authenticationFailedException);

		IOException e = Assertions.assertThrows(IOException.class, () -> {
			inTest.get(index);
		});
		Assertions.assertSame(authenticationFailedException, e.getCause());
	}

	@Test
	public void testGetThrowsUncheckedExceptionFromLoader() throws IOException, AuthenticationFailedException {
		long index = 42L;
		RuntimeException uncheckedException = new RuntimeException();
		when(chunkLoader.load(index)).thenThrow(uncheckedException);

		RuntimeException e = Assertions.assertThrows(RuntimeException.class, () -> {
			inTest.get(index);
		});
		Assertions.assertSame(uncheckedException, e.getCause());
	}

	@Test
	public void testInvalidateAllInvokesSaverForAllEntriesInCache() throws IOException, AuthenticationFailedException {
		long index = 42L;
		long index2 = 43L;
		ChunkData chunk1 = mock(ChunkData.class);
		ChunkData chunk2 = mock(ChunkData.class);
		when(chunk1.data()).thenReturn(ByteBuffer.allocate(42));
		when(chunk2.data()).thenReturn(ByteBuffer.allocate(23));
		when(chunkLoader.load(index)).thenReturn(chunk1);
		inTest.get(index);
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
			inTest.get(index);
		});
		Assertions.assertSame(ioException, e);
	}

}
