package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

class DirectoryIdProvider {

	private static final int MAX_CACHE_SIZE = 5000;

	private final LoadingCache<Path, String> ids;

	public DirectoryIdProvider() {
		ids = CacheBuilder.newBuilder().maximumSize(MAX_CACHE_SIZE).build(new Loader());
	}

	private static class Loader extends CacheLoader<Path, String> {

		@Override
		public String load(Path dirFilePath) throws IOException {
			if (Files.exists(dirFilePath)) {
				return new String(Files.readAllBytes(dirFilePath), StandardCharsets.UTF_8);
			} else {
				return UUID.randomUUID().toString();
			}
		}

	}

	public String load(Path dirFilePath) throws IOException {
		try {
			return ids.get(dirFilePath);
		} catch (ExecutionException e) {
			throw new IOException("Failed to load contents of directory file at path " + dirFilePath, e);
		}
	}

	public void invalidate(Path dirFilePath) {
		ids.invalidate(dirFilePath);
	}

}
