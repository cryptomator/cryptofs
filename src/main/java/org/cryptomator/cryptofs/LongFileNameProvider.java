/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.base.Throwables;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.WritableByteChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptofs.Constants.METADATA_DIR_NAME;

@CryptoFileSystemScoped
class LongFileNameProvider {

	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final Duration MAX_CACHE_AGE = Duration.ofMinutes(1);
	public static final String LONG_NAME_FILE_EXT = ".lng";

	private final Path metadataRoot;
	private final ReadonlyFlag readonlyFlag;
	private final LoadingCache<String, String> longNames;

	@Inject
	public LongFileNameProvider(@PathToVault Path pathToVault, ReadonlyFlag readonlyFlag) {
		this.metadataRoot = pathToVault.resolve(METADATA_DIR_NAME);
		this.readonlyFlag = readonlyFlag;
		this.longNames = CacheBuilder.newBuilder().expireAfterAccess(MAX_CACHE_AGE).build(new Loader());
	}

	private class Loader extends CacheLoader<String, String> {

		@Override
		public String load(String shortName) throws IOException {
			Path file = resolveMetadataFile(shortName);
			return new String(Files.readAllBytes(file), UTF_8);
		}

	}

	public boolean isDeflated(String possiblyDeflatedFileName) {
		return possiblyDeflatedFileName.endsWith(LONG_NAME_FILE_EXT);
	}

	public String inflate(String shortFileName) throws IOException {
		try {
			return longNames.get(shortFileName);
		} catch (ExecutionException e) {
			Throwables.throwIfInstanceOf(e.getCause(), IOException.class);
			throw new IllegalStateException("Unexpected exception", e);
		}
	}

	public String deflate(String longFileName) {
		byte[] longFileNameBytes = longFileName.getBytes(UTF_8);
		byte[] hash = MessageDigestSupplier.SHA1.get().digest(longFileNameBytes);
		String shortName = BASE32.encode(hash) + LONG_NAME_FILE_EXT;
		String cachedLongName = longNames.getIfPresent(shortName);
		if (cachedLongName == null) {
			longNames.put(shortName, longFileName);
		} else {
			assert cachedLongName.equals(longFileName);
		}
		return shortName;
	}

	private Path resolveMetadataFile(String shortName) {
		return metadataRoot.resolve(shortName.substring(0, 2)).resolve(shortName.substring(2, 4)).resolve(shortName);
	}

	public Optional<DeflatedFileName> getCached(Path ciphertextFile) {
		String shortName = ciphertextFile.getFileName().toString();
		String longName = longNames.getIfPresent(shortName);
		if (longName != null) {
			return Optional.of(new DeflatedFileName(shortName, longName));
		} else {
			return Optional.empty();
		}
	}

	public class DeflatedFileName {

		public final String shortName;
		public final String longName;

		private DeflatedFileName(String shortName, String longName) {
			this.shortName = shortName;
			this.longName = longName;
		}

		public void persist() {
			readonlyFlag.assertWritable();
			try {
				persistInternal();
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		}

		private void persistInternal() throws IOException {
			Path file = resolveMetadataFile(shortName);
			Path fileDir = file.getParent();
			assert fileDir != null : "resolveMetadataFile returned path to a file";
			Files.createDirectories(fileDir);
			try (WritableByteChannel ch = Files.newByteChannel(file, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
				ch.write(UTF_8.encode(longName));
			} catch (FileAlreadyExistsException e) {
				// no-op: if the file already exists, we assume its content to be what we want (or we found a SHA1 collision ;-))
				assert Arrays.equals(Files.readAllBytes(file), longName.getBytes(UTF_8));
			}
		}
	}

}
