/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.base.Splitter;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.Normalizer;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static java.util.Arrays.stream;
import static java.util.Spliterator.IMMUTABLE;
import static java.util.Spliterator.NONNULL;
import static java.util.Spliterator.ORDERED;
import static java.util.Spliterators.spliteratorUnknownSize;
import static java.util.stream.Collectors.toList;
import static org.cryptomator.cryptofs.Constants.DATA_DIR_NAME;
import static org.cryptomator.cryptofs.Constants.DIR_PREFIX;
import static org.cryptomator.cryptofs.Constants.SEPARATOR;

@PerFileSystem
class CryptoPathMapper {

	private static final int MAX_CACHED_CIPHERTEXT_NAMES = 1000;
	private static final int MAX_CACHED_DIR_PATHS = 1000;

	private final Cryptor cryptor;
	private final Path dataRoot;
	private final DirectoryIdProvider dirIdProvider;
	private final LongFileNameProvider longFileNameProvider;
	private final LoadingCache<DirIdAndName, String> ciphertextNames;
	private final LoadingCache<String, Path> directoryPathCache;

	@Inject
	public CryptoPathMapper(@PathToVault Path pathToVault, Cryptor cryptor, DirectoryIdProvider dirIdProvider, LongFileNameProvider longFileNameProvider) {
		this.dataRoot = pathToVault.resolve(DATA_DIR_NAME);
		this.cryptor = cryptor;
		this.dirIdProvider = dirIdProvider;
		this.longFileNameProvider = longFileNameProvider;
		this.ciphertextNames = CacheBuilder.newBuilder().maximumSize(MAX_CACHED_CIPHERTEXT_NAMES).build(CacheLoader.from(this::getCiphertextFileName));
		this.directoryPathCache = CacheBuilder.newBuilder().maximumSize(MAX_CACHED_DIR_PATHS).build(CacheLoader.from(this::resolveDirectoryPath));
	}

	public enum CiphertextFileType {
		FILE(""), DIRECTORY(DIR_PREFIX), SYMLINK("1S");

		private final String prefix;

		CiphertextFileType(String prefix) {
			this.prefix = prefix;
		}

		public String getPrefix() {
			return prefix;
		}
	}

	/**
	 * Verifies that no node exists for the given path. Otherwise a {@link FileAlreadyExistsException} will be thrown.
	 *
	 * @param cleartextPath A path
	 * @throws FileAlreadyExistsException If the node exists
	 * @throws IOException                If any I/O error occurs while attempting to resolve the ciphertext path
	 */
	public void assertNonExisting(CryptoPath cleartextPath) throws FileAlreadyExistsException, IOException {
		try {
			CiphertextFileType type = getCiphertextFileType(cleartextPath);
			throw new FileAlreadyExistsException(cleartextPath.toString(), null, "For this path there is already a " + type.name());
		} catch (NoSuchFileException e) {
			// good!
		}
	}

	public CiphertextFileType getCiphertextFileType(CryptoPath cleartextPath) throws NoSuchFileException, IOException {
		CryptoPath parentPath = cleartextPath.getParent();
		if (parentPath == null) {
			return CiphertextFileType.DIRECTORY; // ROOT
		} else {
			CiphertextDirectory parent = getCiphertextDir(parentPath);
			String cleartextName = cleartextPath.getFileName().toString();
			NoSuchFileException notFound = new NoSuchFileException(cleartextPath.toString());
			for (CiphertextFileType type : CiphertextFileType.values()) {
				String ciphertextName = getCiphertextFileName(parent.dirId, cleartextName, type);
				Path ciphertextPath = parent.path.resolve(ciphertextName);
				try {
					// readattr is the fastest way of checking if a file exists. Doing so in this loop is still
					// 1-2 orders of magnitude faster than iterating over directory contents
					Files.readAttributes(ciphertextPath, BasicFileAttributes.class);
					return type;
				} catch (NoSuchFileException e) {
					notFound.addSuppressed(e);
				}
			}
			throw notFound;
		}
	}

	public Path getCiphertextFilePath(CryptoPath cleartextPath, CiphertextFileType type) throws IOException {
		CryptoPath parentPath = cleartextPath.getParent();
		if (parentPath == null) {
			throw new IllegalArgumentException("Invalid file path (must have a parent)" + cleartextPath);
		}
		CiphertextDirectory parent = getCiphertextDir(parentPath);
		String cleartextName = cleartextPath.getFileName().toString();
		String ciphertextName = getCiphertextFileName(parent.dirId, cleartextName, type);
		return parent.path.resolve(ciphertextName);
	}

	private String getCiphertextFileName(String dirId, String cleartextName, CiphertextFileType fileType) throws IOException {
		String ciphertextName = fileType.getPrefix() + ciphertextNames.getUnchecked(new DirIdAndName(dirId, cleartextName));
		if (ciphertextName.length() > Constants.SHORT_NAMES_MAX_LENGTH) {
			return longFileNameProvider.deflate(ciphertextName);
		} else {
			return ciphertextName;
		}
	}

	private String getCiphertextFileName(DirIdAndName dirIdAndName) {
		return cryptor.fileNameCryptor().encryptFilename(dirIdAndName.name, dirIdAndName.dirId.getBytes(StandardCharsets.UTF_8));
	}

	public Path getCiphertextDirPath(CryptoPath cleartextPath) throws IOException {
		return getCiphertextDir(cleartextPath).path;
	}

	public CiphertextDirectory getCiphertextDir(CryptoPath cleartextPath) throws IOException {
		assert cleartextPath.isAbsolute();
		CryptoPath parentPath = cleartextPath.getParent();
		if (parentPath == null) {
			return new CiphertextDirectory(Constants.ROOT_DIR_ID, directoryPathCache.getUnchecked(Constants.ROOT_DIR_ID));
		} else {
			Path dirIdFile = getCiphertextFilePath(cleartextPath, CiphertextFileType.DIRECTORY);
			return resolveDirectory(dirIdFile);
		}
	}

	public CiphertextDirectory resolveDirectory(Path directoryFile) throws IOException {
		String dirId = dirIdProvider.load(directoryFile);
		Path dirPath = directoryPathCache.getUnchecked(dirId);
		return new CiphertextDirectory(dirId, dirPath);
	}

	private Path resolveDirectoryPath(String dirId) {
		String dirHash = cryptor.fileNameCryptor().hashDirectoryId(dirId);
		return dataRoot.resolve(dirHash.substring(0, 2)).resolve(dirHash.substring(2));
	}

	public static class CiphertextDirectory {
		public final String dirId;
		public final Path path;

		public CiphertextDirectory(String dirId, Path path) {
			this.dirId = dirId;
			this.path = path;
		}
	}

	private static class DirIdAndName {
		public final String dirId;
		public final String name;

		public DirIdAndName(String dirId, String name) {
			this.dirId = Objects.requireNonNull(dirId);
			this.name = Objects.requireNonNull(name);
		}

		@Override
		public int hashCode() {
			return Objects.hash(dirId, name);
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			} else if (obj instanceof DirIdAndName) {
				DirIdAndName other = (DirIdAndName) obj;
				return this.dirId.equals(other.dirId) && this.name.equals(other.name);
			} else {
				return false;
			}
		}
	}

}
