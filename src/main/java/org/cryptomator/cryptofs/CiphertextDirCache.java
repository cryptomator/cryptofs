package org.cryptomator.cryptofs;

import com.github.benmanes.caffeine.cache.AsyncCache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * Caches for the cleartext path of a directory its ciphertext path to the content directory.
 */
public class CiphertextDirCache {

	private static final int MAX_CACHED_PATHS = 5000;
	private static final Duration MAX_CACHE_AGE = Duration.ofSeconds(20);

	private final AsyncCache<CryptoPath, CiphertextDirectory> ciphertextDirectories = Caffeine.newBuilder() //
			.maximumSize(MAX_CACHED_PATHS) //
			.expireAfterWrite(MAX_CACHE_AGE) //
			.buildAsync();

	/**
	 * Removes all (key,value) entries, where {@code key.startsWith(oldPrefix) == true}.
	 *
	 * @param basePrefix The prefix key which the keys are checked against
	 */
	void removeAllKeysWithPrefix(CryptoPath basePrefix) {
		ciphertextDirectories.asMap().keySet().removeIf(p -> p.startsWith(basePrefix));
	}

	/**
	 * Remaps all (key,value) entries, where {@code key.startsWith(oldPrefix) == true}.
	 * The new key is computed by replacing the oldPrefix with the newPrefix.
	 *
	 * @param oldPrefix the prefix key which the keys are checked against
	 * @param newPrefix the prefix key which replaces {@code oldPrefix}
	 */
	void recomputeAllKeysWithPrefix(CryptoPath oldPrefix, CryptoPath newPrefix) {
		var remappedEntries = new ArrayList<CacheEntry>();
		ciphertextDirectories.asMap().entrySet().removeIf(e -> {
			if (e.getKey().startsWith(oldPrefix)) {
				var remappedPath = newPrefix.resolve(oldPrefix.relativize(e.getKey()));
				return remappedEntries.add(new CacheEntry(remappedPath, e.getValue()));
			} else {
				return false;
			}
		});
		remappedEntries.forEach(e -> ciphertextDirectories.put(e.clearPath(), e.cipherDir()));
	}


	/**
	 * Gets the cipher directory for the given cleartext path. If a cache miss occurs, the mapping is loaded with the {@code ifAbsent} function.
	 * @param cleartextPath Cleartext path key
	 * @param ifAbsent Function to compute the (cleartextPath, cipherDir) mapping on a cache miss.
	 * @return a {@link CiphertextDirectory}, containing the dirId and the ciphertext content directory path
	 * @throws IOException if the loading function throws an IOException (also if it was invoked by a concurrent call for the same path)
	 */
	CiphertextDirectory get(CryptoPath cleartextPath, CipherDirLoader ifAbsent) throws IOException {
		var futureMapping = new CompletableFuture<CiphertextDirectory>();
		var currentMapping = ciphertextDirectories.asMap().putIfAbsent(cleartextPath, futureMapping);
		if (currentMapping != null) {
			try {
				return currentMapping.join();
			} catch (CompletionException e) {
				if (e.getCause() instanceof IOException ioe) {
					throw ioe;
				}
				throw e;
			}
		} else {
			try {
				futureMapping.complete(ifAbsent.load());
			} catch (Throwable t) {
				// the loader runs outside the atomic context, so the pending entry must be discarded manually. Otherwise, it never completes and blocks all subsequent callers
				ciphertextDirectories.asMap().remove(cleartextPath, futureMapping);
				futureMapping.completeExceptionally(t);
				throw t;
			}
			return futureMapping.join();
		}
	}

	@FunctionalInterface
	interface CipherDirLoader {

		CiphertextDirectory load() throws IOException;
	}

	private record CacheEntry(CryptoPath clearPath, CompletableFuture<CiphertextDirectory> cipherDir) {

	}

}
