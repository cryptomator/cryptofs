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
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.concurrent.ExecutionException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptofs.common.Constants.DEFLATED_FILE_SUFFIX;
import static org.cryptomator.cryptofs.common.Constants.INFLATED_FILE_NAME;

@CryptoFileSystemScoped
public class LongFileNameProvider {

	public static final int MAX_FILENAME_BUFFER_SIZE = 10 * 1024; // no sane person gives a file a 10kb long name.

	private static final BaseEncoding BASE64 = BaseEncoding.base64Url();
	private static final Duration MAX_CACHE_AGE = Duration.ofMinutes(1);

	private final ReadonlyFlag readonlyFlag;
	private final LoadingCache<Path, String> longNames; // Maps from c9s paths to inflated filenames

	@Inject
	public LongFileNameProvider(ReadonlyFlag readonlyFlag) {
		this.readonlyFlag = readonlyFlag;
		this.longNames = CacheBuilder.newBuilder().expireAfterAccess(MAX_CACHE_AGE).build(new Loader());
	}

	private class Loader extends CacheLoader<Path, String> {

		@Override
		public String load(Path c9sPath) throws IOException {
			Path longNameFile = c9sPath.resolve(INFLATED_FILE_NAME);
			try (SeekableByteChannel ch = Files.newByteChannel(longNameFile, StandardOpenOption.READ)) {
				if (ch.size() > MAX_FILENAME_BUFFER_SIZE) {
					throw new IOException("Unexpectedly large file: " + longNameFile);
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
		return possiblyDeflatedFileName.endsWith(DEFLATED_FILE_SUFFIX);
	}

	public String inflate(Path c9sPath) throws IOException {
		try {
			return longNames.get(c9sPath);
		} catch (ExecutionException e) {
			Throwables.throwIfInstanceOf(e.getCause(), IOException.class);
			throw new IllegalStateException("Unexpected exception", e);
		}
	}

	public DeflatedFileName deflate(Path c9rPath) {
		String longFileName = c9rPath.getFileName().toString();
		byte[] longFileNameBytes = longFileName.getBytes(UTF_8);
		byte[] hash = MessageDigestSupplier.SHA1.get().digest(longFileNameBytes);
		String shortName = BASE64.encode(hash) + DEFLATED_FILE_SUFFIX;
		Path c9sPath = c9rPath.resolveSibling(shortName);
		longNames.put(c9sPath, longFileName);
		return new DeflatedFileName(c9sPath, longFileName, readonlyFlag);
	}

	public static class DeflatedFileName {

		public final Path c9sPath;
		public final String longName;
		private final ReadonlyFlag readonlyFlag;

		DeflatedFileName(Path c9sPath, String longName, ReadonlyFlag readonlyFlag) {
			this.c9sPath = c9sPath;
			this.longName = longName;
			this.readonlyFlag = readonlyFlag;
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
			Path longNameFile = c9sPath.resolve(INFLATED_FILE_NAME);
			Files.createDirectories(c9sPath);
			Files.writeString(longNameFile, longName, UTF_8, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
		}
	}

}
