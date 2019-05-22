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
import com.google.common.util.concurrent.UncheckedExecutionException;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptofs.Constants.METADATA_DIR_NAME;

@CryptoFileSystemScoped
class LongFileNameProvider {

	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final Duration MAX_CACHE_AGE = Duration.ofMinutes(1);
	public static final String LONG_NAME_FILE_EXT = ".lng";

	private final Path metadataRoot;
	private final LoadingCache<String, String> longNames;

	@Inject
	public LongFileNameProvider(@PathToVault Path pathToVault) {
		this.metadataRoot = pathToVault.resolve(METADATA_DIR_NAME);
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

	public void persistCachedIfDeflated(Path ciphertextFile) throws IOException {
		String filename = ciphertextFile.getFileName().toString();
		if (isDeflated(filename)) {
			persistCached(filename);
		}
	}

	// visible for testing
	void persistCached(String shortName) throws IOException {
		String longName = longNames.getIfPresent(shortName);
		if (longName == null) {
			throw new IllegalStateException("Long name for " + shortName + " has not been shortened within the last " + MAX_CACHE_AGE);
		}
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

	private Path resolveMetadataFile(String shortName) {
		return metadataRoot.resolve(shortName.substring(0, 2)).resolve(shortName.substring(2, 4)).resolve(shortName);
	}

}
