package org.cryptomator.cryptofs.fh;

import com.google.common.base.Throwables;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalNotification;
import com.google.common.util.concurrent.UncheckedExecutionException;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.concurrent.ExecutionException;

@OpenFileScoped
public class ChunkCache {

	public static final int MAX_CACHED_CLEARTEXT_CHUNKS = 5;

	private final ChunkLoader chunkLoader;
	private final ChunkSaver chunkSaver;
	private final CryptoFileSystemStats stats;
	private final Cache<Long, ChunkData> chunks;

	@Inject
	public ChunkCache(ChunkLoader chunkLoader, ChunkSaver chunkSaver, CryptoFileSystemStats stats) {
		this.chunkLoader = chunkLoader;
		this.chunkSaver = chunkSaver;
		this.stats = stats;
		this.chunks = CacheBuilder.newBuilder() //
				.maximumSize(MAX_CACHED_CLEARTEXT_CHUNKS) //
				.removalListener(this::removeChunk) //
				.build();
	}

	private ChunkData loadChunk(long chunkIndex) throws IOException {
		stats.addChunkCacheMiss();
		try {
			return chunkLoader.load(chunkIndex);
		} catch (AuthenticationFailedException e) {
			// TODO provide means to pass an AuthenticationFailedException handler using an OpenOption
			throw new IOException("Unauthentic ciphertext in chunk " + chunkIndex, e);
		}
	}

	private void removeChunk(RemovalNotification<Long, ChunkData> removal) {
		try {
			chunkSaver.save(removal.getKey(), removal.getValue());
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	public ChunkData get(long chunkIndex) throws IOException {
		try {
			stats.addChunkCacheAccess();
			return chunks.get(chunkIndex, () -> loadChunk(chunkIndex));
		} catch (ExecutionException e) {
			assert e.getCause() instanceof IOException; // the only checked exception thrown by #loadChunk(long)
			throw (IOException) e.getCause();
		}
	}

	public void set(long chunkIndex, ChunkData data) {
		chunks.put(chunkIndex, data);
	}

	public void invalidateAll() {
		chunks.invalidateAll();
	}
}
