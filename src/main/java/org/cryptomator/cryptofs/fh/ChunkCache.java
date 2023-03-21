package org.cryptomator.cryptofs.fh;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.CaffeineSpec;
import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.Scheduler;
import com.google.common.base.Preconditions;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.BiFunction;

@OpenFileScoped
public class ChunkCache {

	public static final int MAX_CACHED_CLEARTEXT_CHUNKS = 5;

	private final ChunkLoader chunkLoader;
	private final ChunkSaver chunkSaver;
	private final CryptoFileSystemStats stats;
	private final BufferPool bufferPool;
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final ConcurrentMap<Long, Chunk> staleChunks;
	private final ConcurrentMap<Long, Chunk> activeChunks;

	/**
	 * This lock ensures no chunks are passed between stale and active state while flushing,
	 * as flushing requires iteration over both sets.
	 */
	private final ReadWriteLock flushLock = new ReentrantReadWriteLock();

	@Inject
	public ChunkCache(ChunkLoader chunkLoader, ChunkSaver chunkSaver, CryptoFileSystemStats stats, BufferPool bufferPool, ExceptionsDuringWrite exceptionsDuringWrite) {
		this.chunkLoader = chunkLoader;
		this.chunkSaver = chunkSaver;
		this.stats = stats;
		this.bufferPool = bufferPool;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.staleChunks = Caffeine.newBuilder() //
				.maximumSize(MAX_CACHED_CLEARTEXT_CHUNKS) //
				.evictionListener(this::evictStaleChunk) //
				.build() //
				.asMap();
		this.activeChunks = new ConcurrentHashMap<>();
	}

	/**
	 * Overwrites data at the given index and increments the access counter of the returned chunk
	 *
	 * @param chunkIndex Which chunk to overwrite
	 * @param chunkData The cleartext data
	 * @return The chunk
	 * @throws IllegalArgumentException If {@code chunkData}'s remaining bytes is not equal to the number of bytes fitting into a chunk
	 */
	public Chunk putChunk(long chunkIndex, ByteBuffer chunkData) throws IllegalArgumentException {
		return activeChunks.compute(chunkIndex, (index, chunk) -> {
			if (chunk == null) {
				chunk = new Chunk(chunkData, true, () -> releaseChunk(chunkIndex));
			} else {
				var dst = chunk.data().duplicate().clear();
				Preconditions.checkArgument(chunkData.remaining() == dst.remaining());
				dst.put(chunkData);
				chunk.dirty().set(true);
			}
			chunk.currentAccesses().incrementAndGet();
			return chunk;
		});
	}

	/**
	 * Returns the chunk for the given index, potentially loading the chunk into cache
	 *
	 * @param chunkIndex Which chunk to load
	 * @return The chunk
	 * @throws IOException If reading or decrypting the chunk failed
	 */
	public Chunk getChunk(long chunkIndex) throws IOException {
		var lock = flushLock.readLock();
		lock.lock();
		try {
			stats.addChunkCacheAccess();
			return activeChunks.compute(chunkIndex, this::acquireInternal);
		} catch (UncheckedIOException | AuthenticationFailedException e) {
			throw new IOException(e);
		} finally {
			lock.unlock();
		}
	}

	private Chunk acquireInternal(Long index, Chunk activeChunk) throws AuthenticationFailedException, UncheckedIOException {
		Chunk result = activeChunk;
		if (result == null) {
			result = staleChunks.remove(index);
			assert result == null || result.currentAccesses().get() == 0;
		}
		if (result == null) {
			result = loadChunk(index);
		}

		assert result != null;
		result.currentAccesses().incrementAndGet();
		return result;
	}

	private Chunk loadChunk(long chunkIndex) throws AuthenticationFailedException, UncheckedIOException {
		stats.addChunkCacheMiss();
		try {
			return new Chunk(chunkLoader.load(chunkIndex), false, () -> releaseChunk(chunkIndex));
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	@SuppressWarnings("resource")
	private void releaseChunk(long chunkIndex) {
		var lock = flushLock.readLock();
		lock.lock();
		try {
			activeChunks.compute(chunkIndex, (index, chunk) -> {
				assert chunk != null;
				var accessCnt = chunk.currentAccesses().decrementAndGet();
				if (accessCnt == 0) {
					staleChunks.put(index, chunk);
					return null; //chunk is stale, remove from active
				} else {
					assert accessCnt > 0;
					return chunk; //keep active
				}
			});
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Flushes cached data (but keeps them cached).
	 * @see #invalidateAll()
	 */
	public void flush() throws IOException {
		var lock = flushLock.writeLock();
		lock.lock();
		BiFunction<Long, Chunk, Chunk> saveUnchecked = (index, chunk) -> {
			try {
				chunkSaver.save(index, chunk);
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
			return chunk;
		};
		try {
			activeChunks.replaceAll(saveUnchecked);
			staleChunks.replaceAll(saveUnchecked);
		} catch (UncheckedIOException e) {
			throw new IOException(e);
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Removes stale chunks from cache.
	 */
	public void invalidateAll() {
		var lock = flushLock.writeLock();
		lock.lock();
		try {
			staleChunks.clear();
		} finally {
			lock.unlock();
		}
	}

	// visible for testing
	void evictStaleChunk(Long index, Chunk chunk, RemovalCause removalCause) {
		assert removalCause != RemovalCause.EXPLICIT; // as per spec of Caffeine#evictionListener(RemovalListener)
		assert chunk.currentAccesses().get() == 0;
		try {
			chunkSaver.save(index, chunk);
		} catch (IOException e) {
			exceptionsDuringWrite.add(e);
		}
		bufferPool.recycle(chunk.data());
	}
}
