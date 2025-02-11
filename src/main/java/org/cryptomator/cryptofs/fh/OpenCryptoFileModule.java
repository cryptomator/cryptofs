package org.cryptomator.cryptofs.fh;

import dagger.Module;
import dagger.Provides;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Module
public class OpenCryptoFileModule {

	@Provides
	@OpenFileScoped
	public ReadWriteLock provideReadWriteLock() {
		return new ReentrantReadWriteLock();
	}

	@Provides
	@OpenFileScoped
	@CurrentOpenFilePaths
	public AtomicReference<ClearAndCipherPath> provideCurrentPaths(@OriginalOpenFilePaths ClearAndCipherPath paths) {
		return new AtomicReference<>(paths);
	}

	@Provides
	@OpenFileScoped
	@OpenFileModifiedDate
	public AtomicReference<Instant> provideLastModifiedDate(@OriginalOpenFilePaths ClearAndCipherPath originalPaths) {
		Instant lastModifiedDate = readBasicAttributes(originalPaths.ciphertextPath()).map(BasicFileAttributes::lastModifiedTime).map(FileTime::toInstant).orElse(Instant.EPOCH);
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
