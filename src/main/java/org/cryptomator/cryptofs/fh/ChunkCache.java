package org.cryptomator.cryptofs.fh;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import com.google.common.base.Preconditions;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonWritableChannelException;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@OpenFileScoped
public class ChunkCache {

	public static final int MAX_CACHED_CLEARTEXT_CHUNKS = 5;

	private final ChunkLoader chunkLoader;
	private final ChunkSaver chunkSaver;
	private final CryptoFileSystemStats stats;
	private final BufferPool bufferPool;
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final Cache<Long, Chunk> chunkCache;
	private final ConcurrentMap<Long, Chunk> cachedChunks;

	/**
	 * We have to deal with two forms of access to the {@link #chunkCache}:
	 * <ol>
	 *     <li>Accessing a single chunk (with a known index), e.g. during {@link #getChunk(long)}</li>
	 *     <li>Accessing multiple chunks, e.g. during {@link #invalidateStale()}</li>
	 * </ol>
	 * <p>
	 * While the former can be handled by the cache implementation (based on {@link ConcurrentMap}) just fine,
	 * we need to make sure no concurrent modification will happen accessing multiple chunks (e.g. when iterating over the entry set).
	 * <p>
	 * This is achieved using this {@link ReadWriteLock}, where holding the {@link ReadWriteLock#readLock() shared lock} is
	 * sufficient for index-based access, while the {@link ReadWriteLock#writeLock() exclusive lock} is necessary otherwise.
	 */
	private final ReadWriteLock lock = new ReentrantReadWriteLock();
	private final Lock sharedLock = lock.readLock(); // required when accessing a single chunk
	private final Lock exclusiveLock = lock.writeLock(); // required when accessing multiple chunks at once

	@Inject
	public ChunkCache(ChunkLoader chunkLoader, ChunkSaver chunkSaver, CryptoFileSystemStats stats, BufferPool bufferPool, ExceptionsDuringWrite exceptionsDuringWrite) {
		this.chunkLoader = chunkLoader;
		this.chunkSaver = chunkSaver;
		this.stats = stats;
		this.bufferPool = bufferPool;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.chunkCache = Caffeine.newBuilder() //
				.maximumWeight(MAX_CACHED_CLEARTEXT_CHUNKS) //
				.weigher(this::weigh) //
				.executor(Runnable::run) // run `evictStaleChunk` in same thread -> see https://github.com/cryptomator/cryptofs/pull/163#issuecomment-1505249736
				.evictionListener(this::evictStaleChunk) //
				.build();
		this.cachedChunks = chunkCache.asMap();
	}

	private int weigh(Long index, Chunk chunk) {
		if (chunk.currentAccesses().get() > 0) {
			return 0; // zero, if currently in use -> avoid maximum size eviction
		} else {
			return 1;
		}
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
		sharedLock.lock();
		try {
			return cachedChunks.compute(chunkIndex, (index, chunk) -> {
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
		} finally {
			sharedLock.unlock();
		}
	}

	/**
	 * Returns the chunk for the given index, potentially loading the chunk into cache
	 *
	 * @param chunkIndex Which chunk to load
	 * @return The chunk
	 * @throws IOException If reading or decrypting the chunk failed
	 */
	public Chunk getChunk(long chunkIndex) throws IOException {
		sharedLock.lock();
		try {
			stats.addChunkCacheAccess();
			try {
				return cachedChunks.compute(chunkIndex, (idx, chunk) -> {
					if (chunk == null) {
						chunk = loadChunk(idx);
					}
					chunk.currentAccesses().incrementAndGet();
					return chunk;
				});
			} catch (UncheckedIOException | AuthenticationFailedException e) {
				throw new IOException(e);
			}
		} finally {
			sharedLock.unlock();
		}
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
		sharedLock.lock();
		try {
			cachedChunks.computeIfPresent(chunkIndex, (idx, chunk) -> {
				chunk.currentAccesses().decrementAndGet();
				return chunk;
			});
		} finally {
			sharedLock.unlock();
		}
	}

	/**
	 * Flushes cached data (but keeps them cached).
	 *
	 * @see #invalidateStale()
	 */
	public void flush() throws IOException {
		exclusiveLock.lock();
		try {
			cachedChunks.forEach((index, chunk) -> {
				try {
					chunkSaver.save(index, chunk);
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			});
		} catch (UncheckedIOException e) {
			throw new IOException(e);
		} finally {
			exclusiveLock.unlock();
		}
	}

	/**
	 * Removes stale chunks from cache.
	 */
	public void invalidateStale() {
		exclusiveLock.lock();
		try {
			cachedChunks.entrySet().removeIf(entry -> entry.getValue().currentAccesses().get() == 0);
		} finally {
			exclusiveLock.unlock();
		}
	}

	// visible for testing
	void evictStaleChunk(Long index, Chunk chunk, RemovalCause removalCause) {
		assert removalCause != RemovalCause.EXPLICIT; // as per spec of Caffeine#evictionListener(RemovalListener)
		assert chunk.currentAccesses().get() == 0;
		try {
			chunkSaver.save(index, chunk);
		} catch (IOException | NonWritableChannelException e) {
			exceptionsDuringWrite.add(e);
		}
		bufferPool.recycle(chunk.data());
	}
}
