package org.cryptomator.cryptofs;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import javax.inject.Inject;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.LoadingCache;

@PerOpenFile
class ChunkCache {

	public static final int MAX_CACHED_CLEARTEXT_CHUNKS = 5;

	private final LoadingCache<Long, ChunkData> chunks;

	@Inject
	public ChunkCache(ChunkLoader chunkLoader, ChunkSaver chunkSaver) {
		this.chunks = CacheBuilder.newBuilder() //
				.maximumSize(MAX_CACHED_CLEARTEXT_CHUNKS) //
				.removalListener(chunkSaver) //
				.build(chunkLoader);
	}

	public ChunkData get(long chunkIndex) throws IOException {
		try {
			return chunks.get(chunkIndex);
		} catch (ExecutionException e) {
			if (e.getCause() instanceof AuthenticationFailedException) {
				// TODO provide means to pass an AuthenticationFailedException handler using an OpenOption
				throw new IOException(e.getCause());
			} else if (e.getCause() instanceof IOException) {
				throw (IOException) e.getCause();
			} else {
				throw new IllegalStateException("Unexpected Exception", e);
			}
		}
	}

	public void set(long chunkIndex, ChunkData data) {
		chunks.put(chunkIndex, data);
	}

	public void invalidateAll() {
		chunks.invalidateAll();
	}
}
