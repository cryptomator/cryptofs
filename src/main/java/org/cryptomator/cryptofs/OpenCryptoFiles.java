package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.OpenCryptoFile.anOpenCryptoFile;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.cryptomator.cryptolib.api.Cryptor;

class OpenCryptoFiles {

	private final ConcurrentMap<Object, OpenCryptoFile> openCryptoFiles = new ConcurrentHashMap<>();
	private final boolean readonly;

	public OpenCryptoFiles(boolean readonly) {
		this.readonly = readonly;
	}

	public OpenCryptoFile get(Path p, Cryptor cryptor, EffectiveOpenOptions options) throws IOException {
		if (options.writable() && readonly) {
			throw new UnsupportedOperationException("read-only file system.");
		}

		try {
			return getExisting(p, cryptor, options);
		} catch (NoSuchFileException e) {
			if (options.writable() && (options.create() || options.createNew())) {
				return createNew(p, cryptor, options);
			} else {
				throw new NoSuchFileException(p.toString());
			}
		}
	}

	/**
	 * @throws NoSuchFileException If no file for the given path exists.
	 */
	private OpenCryptoFile getExisting(Path p, Cryptor cryptor, EffectiveOpenOptions options) throws NoSuchFileException, IOException {
		FileSystemProvider provider = p.getFileSystem().provider();
		BasicFileAttributes attr = provider.readAttributes(p, BasicFileAttributes.class);
		Object id = Optional.ofNullable(attr.fileKey()).orElse(p.toAbsolutePath().normalize());
		return openCryptoFiles.computeIfAbsent(id, ignored -> wrapIOExceptionOf(() -> {
			FileChannel ch = provider.newFileChannel(p, options.createOpenOptionsForEncryptedFile());
			OpenCryptoFile.Builder builder = openCryptoFileBuilder(cryptor, id, ch, options);
			return builder.build();
		}));
	}

	private OpenCryptoFile createNew(Path p, Cryptor cryptor, EffectiveOpenOptions options) throws IOException {
		synchronized (openCryptoFiles) {
			FileSystemProvider provider = p.getFileSystem().provider();
			FileChannel ch = provider.newFileChannel(p, options.createOpenOptionsForNonExistingEncryptedFile());
			BasicFileAttributes attr = provider.readAttributes(p, BasicFileAttributes.class);
			Object id = Optional.ofNullable(attr.fileKey()).orElse(p.toAbsolutePath().normalize());
			OpenCryptoFile.Builder builder = openCryptoFileBuilder(cryptor, id, ch, options);
			OpenCryptoFile file = builder.build();
			return openCryptoFiles.compute(id, (key, value) -> {
				if (value == null) {
					return file;
				} else {
					throw new IllegalStateException("Multiple mappings for newly created file");
				}
			});
		}
	}

	private OpenCryptoFile.Builder openCryptoFileBuilder(Cryptor cryptor, Object id, FileChannel ch, EffectiveOpenOptions options) {
		return anOpenCryptoFile().withCryptor(cryptor).withId(id).withChannel(ch).withOptions(options).onClosed(closed -> openCryptoFiles.remove(closed.id()));
	}

	private static <T> T wrapIOExceptionOf(SupplierThrowingException<T, IOException> supplier) {
		return supplier.wrapExceptionUsing(UncheckedIOException::new).get();
	}

}
