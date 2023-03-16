package org.cryptomator.cryptofs.fh;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalCause;
import com.google.common.cache.RemovalNotification;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@OpenFileScoped
public class ChunkCache {

	public static final int MAX_CACHED_CLEARTEXT_CHUNKS = 5;

	private final ChunkLoader chunkLoader;
	private final ChunkSaver chunkSaver;
	private final CryptoFileSystemStats stats;
	private final BufferPool bufferPool;
	private final Cache<Long, Chunk> staleChunks;
	private final ConcurrentMap<Long, Chunk> activeChunks;

	@Inject
	public ChunkCache(ChunkLoader chunkLoader, ChunkSaver chunkSaver, CryptoFileSystemStats stats, BufferPool bufferPool) {
		this.chunkLoader = chunkLoader;
		this.chunkSaver = chunkSaver;
		this.stats = stats;
		this.bufferPool = bufferPool;
		this.staleChunks = CacheBuilder.newBuilder() //
				.maximumSize(MAX_CACHED_CLEARTEXT_CHUNKS) //
				.removalListener(this::evictChunk) //
				.build();
		this.activeChunks = new ConcurrentHashMap<>();
	}

	private Chunk loadChunk(long chunkIndex) throws AuthenticationFailedException, UncheckedIOException {
		stats.addChunkCacheMiss();
		try {
			return new Chunk(chunkLoader.load(chunkIndex), false, () -> releaseChunk(chunkIndex));
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private synchronized void evictChunk(RemovalNotification<Long, Chunk> removal) {
		try {
			if (removal.getCause() != RemovalCause.EXPLICIT) {
				chunkSaver.save(removal.getKey(), removal.getValue());
				bufferPool.recycle(removal.getValue().data());
			}
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	public void releaseChunk(long chunkIndex) {
		activeChunks.compute(chunkIndex, (index, chunk) -> {
			assert chunk != null;
			if (chunk.currentAccesses().decrementAndGet() == 0) {
				staleChunks.put(index, chunk);
				return null; //chunk is stale, remove from active
			} else {
				return chunk; //keep active
			}
		});
	}

	public Chunk acquireChunk(long chunkIndex) throws IOException {
		try {
			stats.addChunkCacheAccess();
			return activeChunks.compute(chunkIndex, this::internalCompute);
		} catch (UncheckedIOException | AuthenticationFailedException e) {
			throw new IOException(e);
		}
	}


	private Chunk internalCompute(Long index, Chunk activeChunk) throws AuthenticationFailedException, UncheckedIOException {
		Chunk result = activeChunk;
		if (result == null) {
			//check stale and put into active
			result = staleChunks.getIfPresent(index);
			staleChunks.invalidate(index);
		}
		if (result == null) {
			//load chunk
			result = loadChunk(index);
		}

		assert result != null;
		result.currentAccesses().incrementAndGet();
		return result;
	}

	public void set(long chunkIndex, Chunk data) {
		staleChunks.put(chunkIndex, data);
	}

	//TODO: needs to be synchronized with the activeChunk map?
	public void invalidateAll() {
		staleChunks.invalidateAll();
	}
}
