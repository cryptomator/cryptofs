package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import javax.inject.Inject;

import com.google.common.cache.CacheLoader;

@PerFileSystem
class DirectoryIdLoader extends CacheLoader<Path, String> {

	@Inject
	public DirectoryIdLoader() {
	}

	@Override
	public String load(Path dirFilePath) throws IOException {
		if (Files.exists(dirFilePath)) {
			byte[] bytes = Files.readAllBytes(dirFilePath);
			if (bytes.length == 0) {
				throw new IOException("Invalid, empty directory file: " + dirFilePath);
			}
			return new String(bytes, StandardCharsets.UTF_8);
		} else {
			return UUID.randomUUID().toString();
		}
	}

}
