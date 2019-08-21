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
import org.cryptomator.cryptofs.migration.v7.UninflatableFileException;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
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

@CryptoFileSystemScoped
class LongFileNameProvider {

	private static final int MAX_FILENAME_BUFFER_SIZE = 10 * 1024; // no sane person gives a file a 10kb long name.
	private static final BaseEncoding BASE64 = BaseEncoding.base64Url();
	private static final Duration MAX_CACHE_AGE = Duration.ofMinutes(1);
	public static final String SHORTENED_NAME_EXT = ".c9s";
	private static final String LONG_NAME_FILE = "name.c9s";

	private final ReadonlyFlag readonlyFlag;
	private final LoadingCache<Path, String> longNames;

	@Inject
	public LongFileNameProvider(ReadonlyFlag readonlyFlag) {
		this.readonlyFlag = readonlyFlag;
		this.longNames = CacheBuilder.newBuilder().expireAfterAccess(MAX_CACHE_AGE).build(new Loader());
	}

	private class Loader extends CacheLoader<Path, String> {

		@Override
		public String load(Path c9sPath) throws IOException {
			Path longNameFile = c9sPath.resolve(LONG_NAME_FILE);
			try (SeekableByteChannel ch = Files.newByteChannel(longNameFile, StandardOpenOption.READ)) {
				if (ch.size() > MAX_FILENAME_BUFFER_SIZE) {
					throw new UninflatableFileException("Unexpectedly large file: " + longNameFile);
				}
				assert ch.size() <= MAX_FILENAME_BUFFER_SIZE;
				ByteBuffer buf = ByteBuffer.allocate((int) ch.size());
				ch.read(buf);
				buf.flip();
				return UTF_8.decode(buf).toString();
			}
		}

	}

	public boolean isDeflated(String possiblyDeflatedFileName) {
		return possiblyDeflatedFileName.endsWith(SHORTENED_NAME_EXT);
	}

	public String inflate(Path c9sPath) throws IOException {
		try {
			return longNames.get(c9sPath);
		} catch (ExecutionException e) {
			Throwables.throwIfInstanceOf(e.getCause(), IOException.class);
			throw new IllegalStateException("Unexpected exception", e);
		}
	}

	public Path deflate(Path canonicalFileName) {
		String longFileName = canonicalFileName.getFileName().toString();
		byte[] longFileNameBytes = longFileName.getBytes(UTF_8);
		byte[] hash = MessageDigestSupplier.SHA1.get().digest(longFileNameBytes);
		String shortName = BASE64.encode(hash) + SHORTENED_NAME_EXT;
		Path result = canonicalFileName.resolveSibling(shortName);
		String cachedLongName = longNames.getIfPresent(shortName);
		if (cachedLongName == null) {
			longNames.put(result, longFileName);
		} else {
			assert cachedLongName.equals(longFileName);
		}
		return result;
	}

	public Optional<DeflatedFileName> getCached(Path c9sPath) {
		String longName = longNames.getIfPresent(c9sPath);
		if (longName != null) {
			return Optional.of(new DeflatedFileName(c9sPath, longName));
		} else {
			return Optional.empty();
		}
	}

	public class DeflatedFileName {

		public final Path c9sPath;
		public final String longName;

		private DeflatedFileName(Path c9sPath, String longName) {
			this.c9sPath = c9sPath;
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
			Path longNameFile = c9sPath.resolve(LONG_NAME_FILE);
			Files.createDirectories(c9sPath);
			try (WritableByteChannel ch = Files.newByteChannel(longNameFile, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
				ch.write(UTF_8.encode(longName));
			}
		}
	}

}
