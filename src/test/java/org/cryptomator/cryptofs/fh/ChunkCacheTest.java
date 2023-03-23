package org.cryptomator.cryptofs.fh;

import com.github.benmanes.caffeine.cache.RemovalCause;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.AccessDeniedException;
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
	private ChunkCache inTest;

	@BeforeEach
	public void setup() {
		 inTest = new ChunkCache(chunkLoader, chunkSaver, stats, bufferPool, exceptionsDuringWrite);
	}

	@Test
	@DisplayName("getChunk() invokes chunkLoader.load() on cache miss")
	public void testGetInvokesLoaderIfEntryNotInCache() throws IOException, AuthenticationFailedException {
		long index = 42L;
		var data = ByteBuffer.allocate(0);
		when(chunkLoader.load(index)).thenReturn(data);

		inTest.getChunk(index);

		verify(chunkLoader).load(index);
		verify(stats).addChunkCacheAccess();
		verify(stats).addChunkCacheMiss();
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

	@Nested
	@DisplayName("With active chunks [1] and stale chunks [42, 43, 44, 45, 46]")
	public class Prepopulated {

		private Chunk activeChunk1;
		private Chunk staleChunk42;
		private Chunk staleChunk43;
		private Chunk staleChunk44;
		private Chunk staleChunk45;
		private Chunk staleChunk46;

		@BeforeEach
		public void setup() {
			Assumptions.assumeTrue(ChunkCache.MAX_CACHED_CLEARTEXT_CHUNKS == 5);

			activeChunk1 = inTest.putChunk(1L, ByteBuffer.allocate(0));
			Assertions.assertEquals(1, activeChunk1.currentAccesses().get());

			staleChunk42 = inTest.putChunk(42L, ByteBuffer.allocate(0));
			staleChunk43 = inTest.putChunk(43L, ByteBuffer.allocate(0));
			staleChunk44 = inTest.putChunk(44L, ByteBuffer.allocate(0));
			staleChunk45 = inTest.putChunk(45L, ByteBuffer.allocate(0));
			staleChunk46 = inTest.putChunk(46L, ByteBuffer.allocate(0));
			staleChunk42.close();
			staleChunk43.close();
			staleChunk44.close();
			staleChunk45.close();
			staleChunk46.close();
			Assertions.assertEquals(0, staleChunk42.currentAccesses().get());
			Assertions.assertEquals(0, staleChunk43.currentAccesses().get());
			Assertions.assertEquals(0, staleChunk44.currentAccesses().get());
			Assertions.assertEquals(0, staleChunk45.currentAccesses().get());
			Assertions.assertEquals(0, staleChunk46.currentAccesses().get());
		}

		@Test
		@DisplayName("getChunk() does not invoke chunkLoader.load() and returns active chunk")
		public void testGetChunkActive() throws IOException {
			var chunk = inTest.getChunk(1L);

			Assertions.assertSame(activeChunk1, chunk);
			Assertions.assertEquals(2, chunk.currentAccesses().get());
			verify(stats).addChunkCacheAccess();
			verifyNoMoreInteractions(stats);
			verifyNoMoreInteractions(chunkLoader);
		}

		@Test
		@DisplayName("getChunk() does not invoke chunkLoader.load() and returns stale chunk")
		public void testGetChunkStale() throws IOException {
			var chunk = inTest.getChunk(42L);

			Assertions.assertSame(staleChunk42, chunk);
			Assertions.assertEquals(1, chunk.currentAccesses().get());
			verify(stats).addChunkCacheAccess();
			verifyNoMoreInteractions(stats);
			verifyNoMoreInteractions(chunkLoader);
		}

		@Test
		@DisplayName("chunk.close() keeps chunk active if access count > 1")
		public void testClosingActiveChunkThatIsReferencedTwice() throws IOException, AuthenticationFailedException {
			try (var chunk = inTest.getChunk(1L)) {
				Assertions.assertSame(activeChunk1, chunk);
				Assertions.assertEquals(2, activeChunk1.currentAccesses().get());
			} // close

			Assertions.assertEquals(1, activeChunk1.currentAccesses().get());
			verifyNoMoreInteractions(chunkSaver);
			verifyNoMoreInteractions(bufferPool);
		}

		@Test
		@DisplayName("chunk.close() triggers eviction of some stale chunk")
		public void testClosingActiveChunkTriggersEvictionOfStaleChunk() throws IOException, AuthenticationFailedException {
			activeChunk1.close();

			inTest.cleanup(); // evict now, don't wait for async task
			// we can't know _which_ stale chunk gets evicted. see https://github.com/ben-manes/caffeine/issues/583
			verify(chunkSaver).save(Mockito.anyLong(), Mockito.any());
			verify(bufferPool).recycle(Mockito.any());
			verifyNoMoreInteractions(chunkSaver);
		}

		@Test
		@DisplayName("flush() saves all stale chunks")
		public void testFlushInvokesSaverForAllStaleChunks() throws IOException, AuthenticationFailedException {
			inTest.flush();

			verify(chunkSaver).save(42L, staleChunk42);
			verify(chunkSaver).save(43L, staleChunk43);
			verify(chunkSaver).save(44L, staleChunk44);
			verify(chunkSaver).save(45L, staleChunk45);
			verify(chunkSaver).save(46L, staleChunk46);
		}

		@Test
		@DisplayName("flush() saves all active chunks")
		public void testFlushInvokesSaverForAllActiveChunks() throws IOException, AuthenticationFailedException {
			try (var activeChunk2 = inTest.putChunk(2L, ByteBuffer.allocate(0))) {
				inTest.flush();

				verify(chunkSaver).save(1L, activeChunk1);
				verify(chunkSaver).save(2L, activeChunk2);
			}
		}

		@Test
		@DisplayName("flush() does not evict cached chunks")
		public void testFlushKeepsItemInCache() throws IOException, AuthenticationFailedException {
			inTest.flush();

			Assertions.assertSame(activeChunk1, inTest.getChunk(1L));
			Assertions.assertSame(staleChunk42, inTest.getChunk(42L));
			verifyNoMoreInteractions(chunkLoader);
		}

		@Test
		@DisplayName("flush() does not evict cached chunks despite I/O error")
		public void testFlushKeepsItemInCacheDespiteIOException() throws IOException, AuthenticationFailedException {
			Mockito.doThrow(new AccessDeniedException("")).when(chunkSaver).save(42L, staleChunk42);

			Assertions.assertThrows(IOException.class, () -> inTest.flush());

			Assertions.assertSame(activeChunk1, inTest.getChunk(1L));
			Assertions.assertSame(staleChunk42, inTest.getChunk(42L));
			verifyNoMoreInteractions(chunkLoader);
		}

		@Test
		@DisplayName("invalidateAll() flushes stale chunks but keeps active chunks")
		public void testInvalidateAll() throws IOException, AuthenticationFailedException {
			when(chunkLoader.load(Mockito.anyLong())).thenReturn(ByteBuffer.allocate(0));

			inTest.invalidateAll();

			Assertions.assertSame(activeChunk1, inTest.getChunk(1L));
			Assertions.assertNotSame(staleChunk42, inTest.getChunk(42L));
			Assertions.assertNotSame(staleChunk43, inTest.getChunk(43L));
			Assertions.assertNotSame(staleChunk44, inTest.getChunk(44L));
			Assertions.assertNotSame(staleChunk45, inTest.getChunk(45L));
			Assertions.assertNotSame(staleChunk46, inTest.getChunk(46L));
			verify(chunkLoader).load(42L);
			verify(chunkLoader).load(43L);
			verify(chunkLoader).load(44L);
			verify(chunkLoader).load(45L);
			verify(chunkLoader).load(46L);
			verifyNoMoreInteractions(chunkLoader);
		}

		@Test
		@DisplayName("putChunk() returns active chunk if already present")
		public void testPutChunkReturnsActiveChunk() {
			activeChunk1.dirty().set(false);

			var chunk = inTest.putChunk(1L, ByteBuffer.allocate(0));

			Assertions.assertSame(activeChunk1, chunk);
			Assertions.assertEquals(2, chunk.currentAccesses().get());
			Assertions.assertTrue(chunk.isDirty());
		}

		@Test
		@DisplayName("putChunk() returns new chunk if neither stale nor active")
		public void testPutChunkReturnsNewChunk() {
			var chunk = inTest.putChunk(100L, ByteBuffer.allocate(0));

			Assertions.assertNotSame(activeChunk1, chunk);
			Assertions.assertNotSame(staleChunk42, chunk);
			Assertions.assertNotSame(staleChunk43, chunk);
			Assertions.assertNotSame(staleChunk44, chunk);
			Assertions.assertNotSame(staleChunk45, chunk);
			Assertions.assertNotSame(staleChunk46, chunk);
			Assertions.assertEquals(1, chunk.currentAccesses().get());
			Assertions.assertTrue(chunk.isDirty());
		}


	}

	@Test
	@DisplayName("IOException during eviction of stale chunks is stored to exceptionsDuringWrite")
	public void testIOExceptionsDuringWriteAreAddedToExceptionsDuringWrite() throws IOException {
		IOException ioException = new IOException();
		Chunk chunk = new Chunk(ByteBuffer.allocate(0), true, () -> {});
		Mockito.doThrow(ioException).when(chunkSaver).save(42L, chunk);

		inTest.evictStaleChunk(42L, chunk, RemovalCause.EXPIRED);

		verify(exceptionsDuringWrite).add(ioException);
	}

}
