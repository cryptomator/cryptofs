package org.cryptomator.cryptofs;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import javax.inject.Inject;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;

@PerOpenFile
class ChunkCache {

	public static final int MAX_CACHED_CLEARTEXT_CHUNKS = 5;

	private final CryptoFileSystemStats stats;
	private final LoadingCache<Long, ChunkData> chunks;

	@Inject
	public ChunkCache(ChunkLoader chunkLoader, ChunkSaver chunkSaver, CryptoFileSystemStats stats) {
		this.stats = stats;
		this.chunks = CacheBuilder.newBuilder() //
				.maximumSize(MAX_CACHED_CLEARTEXT_CHUNKS) //
				.removalListener(removal -> chunkSaver.save((Long) removal.getKey(), (ChunkData) removal.getValue())) //
				.build(new CacheLoader<Long, ChunkData>() {
					@Override
					public ChunkData load(Long key) throws Exception {
						return chunkLoader.load(key);
					}
				});
	}

	public ChunkData get(long chunkIndex) throws IOException {
		try {
			stats.addChunkCacheAccess();
			return chunks.get(chunkIndex);
		} catch (ExecutionException e) {
			throw (IOException) e.getCause();
		} catch (UncheckedExecutionException e) {
			if (e.getCause() instanceof AuthenticationFailedException) {
				// TODO provide means to pass an AuthenticationFailedException handler using an OpenOption
				throw new IOException(e.getCause());
			}
			throw e;
		}
	}

	public void set(long chunkIndex, ChunkData data) {
		chunks.put(chunkIndex, data);
	}

	public void invalidateAll() {
		chunks.invalidateAll();
	}
}
