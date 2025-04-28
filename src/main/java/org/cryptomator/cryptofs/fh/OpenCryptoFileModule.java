package org.cryptomator.cryptofs.fh;

import dagger.Module;
import dagger.Provides;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

@Module
public class OpenCryptoFileModule {

	@Provides
	@OpenFileScoped
	public ReadWriteLock provideReadWriteLock() {
		return new ReentrantReadWriteLock();
	}

	@Provides
	@OpenFileScoped
	@CurrentOpenFilePath
	public AtomicReference<Path> provideCurrentPath(@OriginalOpenFilePath Path originalPath) {
		return new AtomicReference<>(originalPath);
	}

	@Provides
	@OpenFileScoped
	@OpenFileModifiedDate
	public AtomicReference<Instant> provideLastModifiedDate(@OriginalOpenFilePath Path originalPath) {
		Instant lastModifiedDate = readBasicAttributes(originalPath).map(BasicFileAttributes::lastModifiedTime).map(FileTime::toInstant).orElse(Instant.EPOCH);
		return new AtomicReference<>(lastModifiedDate);
	}

	@Provides
	@OpenFileScoped
	@OpenFileSize
	public AtomicLong provideFileSize() {
		// will be initialized when first creating a FileChannel. See OpenCryptoFile#size()
		return new AtomicLong(-1L);
	}

	private Optional<BasicFileAttributes> readBasicAttributes(Path path) {
		try {
			return Optional.of(Files.readAttributes(path, BasicFileAttributes.class));
		} catch (IOException e) {
			return Optional.empty();
		}
	}

}
