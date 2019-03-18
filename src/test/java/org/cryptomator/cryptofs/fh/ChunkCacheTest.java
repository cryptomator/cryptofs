package org.cryptomator.cryptofs.fh;

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class ChunkCacheTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private final ChunkLoader chunkLoader = mock(ChunkLoader.class);
	private final ChunkSaver chunkSaver = mock(ChunkSaver.class);
	private final CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);
	private final ChunkCache inTest = new ChunkCache(chunkLoader, chunkSaver, stats);

	@Test
	public void testGetInvokesLoaderIfEntryNotInCache() throws IOException {
		long index = 42L;
		ChunkData data = mock(ChunkData.class);
		when(chunkLoader.load(index)).thenReturn(data);

		assertThat(inTest.get(index), is(data));
		verify(stats).addChunkCacheAccess();
	}

	@Test
	public void testGetDoesNotInvokeLoaderIfEntryInCacheFromPreviousGet() throws IOException {
		long index = 42L;
		ChunkData data = mock(ChunkData.class);
		when(chunkLoader.load(index)).thenReturn(data);
		inTest.get(index);

		assertThat(inTest.get(index), is(data));
		verify(stats, Mockito.times(2)).addChunkCacheAccess();
		verify(chunkLoader).load(index);
	}

	@Test
	public void testGetDoesNotInvokeLoaderIfEntryInCacheFromPreviousSet() throws IOException {
		long index = 42L;
		ChunkData data = mock(ChunkData.class);
		inTest.set(index, data);

		assertThat(inTest.get(index), is(data));
		verify(stats).addChunkCacheAccess();
	}

	@Test
	public void testGetInvokesSaverIfMaxEntriesInCacheAreReachedAndAnEntryNotInCacheIsRequested() throws IOException {
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
		verifyNoMoreInteractions(chunkSaver);
	}

	@Test
	public void testGetRethrowsAuthenticationFailedExceptionFromLoader() throws IOException {
		long index = 42L;
		AuthenticationFailedException authenticationFailedException = new AuthenticationFailedException("Foo");
		when(chunkLoader.load(index)).thenThrow(authenticationFailedException);

		thrown.expect(IOException.class);
		thrown.expectCause(is(authenticationFailedException));

		inTest.get(index);
	}

	@Test
	public void testGetThrowsUncheckedExceptionFromLoader() throws IOException {
		long index = 42L;
		RuntimeException uncheckedException = new RuntimeException();
		when(chunkLoader.load(index)).thenThrow(uncheckedException);

		thrown.expectCause(is(uncheckedException));

		inTest.get(index);
	}

	@Test
	public void testInvalidateAllInvokesSaverForAllEntriesInCache() throws IOException {
		long index = 42L;
		long index2 = 43L;
		ChunkData data = mock(ChunkData.class);
		ChunkData data2 = mock(ChunkData.class);
		when(chunkLoader.load(index)).thenReturn(data);
		inTest.get(index);
		inTest.set(index2, data2);

		inTest.invalidateAll();

		verify(chunkSaver).save(index, data);
		verify(chunkSaver).save(index2, data2);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testLoaderThrowsOnlyIOException() throws NoSuchMethodException {
		List<Class<?>> exceptionsThrownByLoader = asList(ChunkLoader.class.getMethod("load", Long.class).getExceptionTypes());

		// INFO: when adding exception types here add a corresponding test like testGetRethrowsIOExceptionFromLoader
		assertThat(exceptionsThrownByLoader, containsInAnyOrder(IOException.class));
	}

	@Test
	public void testGetRethrowsIOExceptionFromLoader() throws IOException {
		long index = 42L;
		IOException ioException = new IOException();
		when(chunkLoader.load(index)).thenThrow(ioException);

		thrown.expect(is(ioException));

		inTest.get(index);
	}

}
