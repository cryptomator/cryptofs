package org.cryptomator.cryptofs;

import com.github.benmanes.caffeine.cache.AsyncCache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;

public class ClearToCipherDirCache {

	private static final int MAX_CACHED_PATHS = 5000;
	private static final Duration MAX_CACHE_AGE = Duration.ofSeconds(20);

	private final AsyncCache<CryptoPath, CipherDir> ciphertextDirectories = Caffeine.newBuilder() //
			.maximumSize(MAX_CACHED_PATHS) //
			.expireAfterWrite(MAX_CACHE_AGE) //
			.buildAsync();

	/**
	 * Removes all (key,value) entries, where {@code key.startsWith(oldPrefix) == true}.
	 *
	 * @param basePrefix The prefix key which the keys are checked against
	 */
	void removeAllKeysWithPrefix(CryptoPath basePrefix) {
		//TODO: this a expensive operation
		// with a cachesize of _n_, comparsion cost of _x_ and removal costs of y
		// worstcase runtime is n*(x+y)
		// worstcase example: recursivley deleting a deeply nested dir, where all child dirs are cached
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
		//TODO: this is a very expensive operation
		//  with a  cache size of _n_, comparsion cost of _x_, removal costs of y and insertion costs of z
		//  worstcase runtime is n*x + n*y + n*z
		//  worstcase example: moving the root of a deeply nested dir, where all child dirs are cached
		//  Structure: /foo/bar/foo/bar/foo/bar...; Call: remapWithPrefix(/foo,/seb)
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

	CipherDir putIfAbsent(CryptoPath cleartextPath, CipherDirLoader ifAbsent) throws IOException {
		var futureMapping = new CompletableFuture<CipherDir>();
		var currentMapping = ciphertextDirectories.asMap().putIfAbsent(cleartextPath, futureMapping);
		if (currentMapping != null) {
			return currentMapping.join();
		} else {
			futureMapping.complete(ifAbsent.load());
			return futureMapping.join();
		}
	}

	@FunctionalInterface
	interface CipherDirLoader {

		CipherDir load() throws IOException;
	}

	private record CacheEntry(CryptoPath clearPath, CompletableFuture<CipherDir> cipherDir) {

	}

}
