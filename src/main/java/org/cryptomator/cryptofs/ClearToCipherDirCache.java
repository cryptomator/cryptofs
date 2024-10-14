package org.cryptomator.cryptofs;

import com.github.benmanes.caffeine.cache.AsyncCache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class ClearToCipherDirCache {

	private static final int MAX_CACHED_PATHS = 5000;
	private static final Duration MAX_CACHE_AGE = Duration.ofSeconds(20);

	//TODO: not testable!
	private final AsyncCache<CryptoPath, CipherDir> ciphertextDirectories = Caffeine.newBuilder() //
			.maximumSize(MAX_CACHED_PATHS) //
			.expireAfterWrite(MAX_CACHE_AGE) //
			.buildAsync();

	//TODO: this a expensive operation
	// with a cachesize of _n_ and comparsion cost of _x_
	// runtime is n*x
	void removeAllKeysWithPrefix(CryptoPath basePrefix) {
		ciphertextDirectories.asMap().keySet().removeIf(p -> p.startsWith(basePrefix));
	}

	//TODO: this is a very expensive operation
	//  with a  cache size of _n_ and comparsion cost of _x_
	//  runtime is n*(1+x)
	void recomputeAllKeysWithPrefix(CryptoPath oldPrefix, CryptoPath newPrefix) {
		var remappedEntries = new ArrayList<Map.Entry<CryptoPath, CompletableFuture<CipherDir>>>();
		ciphertextDirectories.asMap().entrySet().removeIf(e -> {
			if (e.getKey().startsWith(oldPrefix)) {
				var remappedPath = newPrefix.resolve(oldPrefix.relativize(e.getKey()));
				return remappedEntries.add(Map.entry(remappedPath, e.getValue()));
			} else {
				return false;
			}
		});
		remappedEntries.forEach(e -> ciphertextDirectories.put(e.getKey(), e.getValue()));
	}

	//cheap operation: log(n)
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

}
