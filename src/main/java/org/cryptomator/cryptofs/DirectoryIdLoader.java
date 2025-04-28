package org.cryptomator.cryptofs;

import com.github.benmanes.caffeine.cache.CacheLoader;
import org.cryptomator.cryptofs.event.BrokenDirFileEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;

import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import java.util.function.Consumer;

@CryptoFileSystemScoped
class DirectoryIdLoader implements CacheLoader<Path, String> {

	private static final int MAX_DIR_ID_LENGTH = 1000;

	private final Consumer<FilesystemEvent> eventConsumer;

	@Inject
	public DirectoryIdLoader(Consumer<FilesystemEvent> eventConsumer) {
		this.eventConsumer = eventConsumer;
	}

	@Override
	public String load(Path dirFilePath) throws IOException {
		try (FileChannel ch = FileChannel.open(dirFilePath, StandardOpenOption.READ);
			 InputStream in = Channels.newInputStream(ch)) {
			long size = ch.size();
			if (size == 0) {
				eventConsumer.accept(new BrokenDirFileEvent(dirFilePath));
				throw new IOException("Invalid, empty directory file: " + dirFilePath);
			} else if (size > MAX_DIR_ID_LENGTH) {
				eventConsumer.accept(new BrokenDirFileEvent(dirFilePath));
				throw new IOException("Unexpectedly large directory file: " + dirFilePath);
			} else {
				assert size <= MAX_DIR_ID_LENGTH; // thus int
				byte[] bytes = in.readNBytes((int) size);
				assert bytes.length == size;
				return new String(bytes, StandardCharsets.UTF_8);
			}
		} catch (NoSuchFileException e) {
			return UUID.randomUUID().toString();
		}
	}

}
