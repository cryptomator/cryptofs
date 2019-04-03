package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

import javax.inject.Inject;

import com.google.common.cache.CacheLoader;

@CryptoFileSystemScoped
class DirectoryIdLoader extends CacheLoader<Path, String> {

	private static final int MAX_DIR_ID_LENGTH = 1000;

	@Inject
	public DirectoryIdLoader() {
	}

	@Override
	public String load(Path dirFilePath) throws IOException {
		try (FileChannel ch = FileChannel.open(dirFilePath, StandardOpenOption.READ)) {
			long size = ch.size();
			if (size == 0) {
				throw new IOException("Invalid, empty directory file: " + dirFilePath);
			} else if (size > MAX_DIR_ID_LENGTH) {
				throw new IOException("Unexpectedly large directory file: " + dirFilePath);
			} else {
				assert size <= MAX_DIR_ID_LENGTH; // thus int
				ByteBuffer buffer = ByteBuffer.allocate((int) size);
				int read = ch.read(buffer);
				assert read == size;
				buffer.flip();
				return StandardCharsets.UTF_8.decode(buffer).toString();
			}
		} catch (NoSuchFileException e) {
			return UUID.randomUUID().toString();
		}
	}

}
