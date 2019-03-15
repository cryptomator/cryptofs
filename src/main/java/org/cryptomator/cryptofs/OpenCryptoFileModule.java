package org.cryptomator.cryptofs;

import dagger.Module;
import dagger.Provides;
import org.cryptomator.cryptolib.api.Cryptor;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.cryptomator.cryptolib.Cryptors.cleartextSize;

@Module
class OpenCryptoFileModule {

	@Provides
	@PerOpenFile
	@CurrentOpenFilePath
	public AtomicReference<Path> provideCurrentPath(@OriginalOpenFilePath Path originalPath) {
		return new AtomicReference<>(originalPath);
	}

	@Provides
	@PerOpenFile
	public Supplier<BasicFileAttributeView> provideBasicFileAttributeViewSupplier(@CurrentOpenFilePath AtomicReference<Path> currentPath) {
		return () -> {
			Path path = currentPath.get();
			return path.getFileSystem().provider().getFileAttributeView(path, BasicFileAttributeView.class);
		};
	}

	@Provides
	@PerOpenFile
	@OpenFileModifiedDate
	public AtomicReference<Instant> provideLastModifiedDate(@OriginalOpenFilePath Path originalPath) {
		Instant lastModifiedDate = readBasicAttributes(originalPath).map(BasicFileAttributes::lastModifiedTime).map(FileTime::toInstant).orElse(Instant.ofEpochMilli(0));
		return new AtomicReference<>(lastModifiedDate);
	}

	@Provides
	@PerOpenFile
	@OpenFileSize
	public AtomicLong provideFileSize(@OriginalOpenFilePath Path originalPath, Cryptor cryptor) {
		long ciphertextSize = readBasicAttributes(originalPath).map(BasicFileAttributes::size).orElse(0l);
		if (ciphertextSize == 0) {
			return new AtomicLong();
		} else {
			int headerSize = cryptor.fileHeaderCryptor().headerSize();
			return new AtomicLong(cleartextSize(ciphertextSize - headerSize, cryptor));
		}
	}

	private Optional<BasicFileAttributes> readBasicAttributes(Path path) {
		try {
			return Optional.of(Files.readAttributes(path, BasicFileAttributes.class));
		} catch (IOException e) {
			return Optional.empty();
		}
	}

}
