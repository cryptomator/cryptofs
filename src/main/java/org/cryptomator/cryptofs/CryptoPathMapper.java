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
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import static org.cryptomator.cryptofs.common.Constants.DATA_DIR_NAME;

@CryptoFileSystemScoped
public class CryptoPathMapper {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoPathMapper.class);
	private static final int MAX_CACHED_CIPHERTEXT_NAMES = 5000;
	private static final int MAX_CACHED_DIR_PATHS = 5000;
	private static final Duration MAX_CACHE_AGE = Duration.ofSeconds(20);

	private final Cryptor cryptor;
	private final Path dataRoot;
	private final DirectoryIdProvider dirIdProvider;
	private final LongFileNameProvider longFileNameProvider;
	private final VaultConfig vaultConfig;
	private final LoadingCache<DirIdAndName, String> ciphertextNames;
	private final Cache<CryptoPath, CiphertextDirectory> ciphertextDirectories;

	private final CiphertextDirectory rootDirectory;

	@Inject
	CryptoPathMapper(@PathToVault Path pathToVault, Cryptor cryptor, DirectoryIdProvider dirIdProvider, LongFileNameProvider longFileNameProvider, VaultConfig vaultConfig) {
		this.dataRoot = pathToVault.resolve(DATA_DIR_NAME);
		this.cryptor = cryptor;
		this.dirIdProvider = dirIdProvider;
		this.longFileNameProvider = longFileNameProvider;
		this.vaultConfig = vaultConfig;
		this.ciphertextNames = CacheBuilder.newBuilder().maximumSize(MAX_CACHED_CIPHERTEXT_NAMES).build(CacheLoader.from(this::getCiphertextFileName));
		this.ciphertextDirectories = CacheBuilder.newBuilder().maximumSize(MAX_CACHED_DIR_PATHS).expireAfterWrite(MAX_CACHE_AGE).build();
		this.rootDirectory = resolveDirectory(Constants.ROOT_DIR_ID);
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
			CiphertextFilePath ciphertextPath = getCiphertextFilePath(cleartextPath);
			BasicFileAttributes attr = Files.readAttributes(ciphertextPath.getRawPath(), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
			if (attr != null) {
				throw new FileAlreadyExistsException(cleartextPath.toString());
			}
		} catch (NoSuchFileException e) {
			// good!
		}
	}

	/**
	 * @param cleartextPath A path
	 * @return The file type for the given path (if it exists)
	 * @throws NoSuchFileException If no node exists at the given path for any known type
	 * @throws IOException
	 */
	public CiphertextFileType getCiphertextFileType(CryptoPath cleartextPath) throws NoSuchFileException, IOException {
		CryptoPath parentPath = cleartextPath.getParent();
		if (parentPath == null) {
			return CiphertextFileType.DIRECTORY; // ROOT
		} else {
			CiphertextFilePath ciphertextPath = getCiphertextFilePath(cleartextPath);
			BasicFileAttributes attr = Files.readAttributes(ciphertextPath.getRawPath(), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
			if (attr.isDirectory()) {
				if (Files.exists(ciphertextPath.getDirFilePath(), LinkOption.NOFOLLOW_LINKS)) {
					return CiphertextFileType.DIRECTORY;
				} else if (Files.exists(ciphertextPath.getSymlinkFilePath(), LinkOption.NOFOLLOW_LINKS)) {
					return CiphertextFileType.SYMLINK;
				} else if (ciphertextPath.isShortened() && Files.exists(ciphertextPath.getFilePath(), LinkOption.NOFOLLOW_LINKS)) {
					return CiphertextFileType.FILE;
				} else {
					LOG.warn("Did not find valid content inside of {}", ciphertextPath.getRawPath());
					throw new NoSuchFileException(cleartextPath.toString(), null, "Could not determine type of file " + ciphertextPath.getRawPath());
				}
			} else {
				// assume "file" if not a directory (even if it isn't a "regular" file, see issue #81):
				return CiphertextFileType.FILE;
			}
		}
	}

	public CiphertextFilePath getCiphertextFilePath(CryptoPath cleartextPath) throws IOException {
		CryptoPath parentPath = cleartextPath.getParent();
		if (parentPath == null) {
			throw new IllegalArgumentException("Invalid file path (must have a parent): " + cleartextPath);
		}
		CiphertextDirectory parent = getCiphertextDir(parentPath);
		String cleartextName = cleartextPath.getFileName().toString();
		return getCiphertextFilePath(parent.path, parent.dirId, cleartextName);
	}
	
	public CiphertextFilePath getCiphertextFilePath(Path parentCiphertextDir, String parentDirId, String cleartextName) {
		String ciphertextName = ciphertextNames.getUnchecked(new DirIdAndName(parentDirId, cleartextName));
		Path c9rPath = parentCiphertextDir.resolve(ciphertextName);
		if (ciphertextName.length() > vaultConfig.getShorteningThreshold()) {
			LongFileNameProvider.DeflatedFileName deflatedFileName = longFileNameProvider.deflate(c9rPath);
			return new CiphertextFilePath(deflatedFileName.c9sPath, Optional.of(deflatedFileName));
		} else {
			return new CiphertextFilePath(c9rPath, Optional.empty());
		}
	}

	private String getCiphertextFileName(DirIdAndName dirIdAndName) {
		return cryptor.fileNameCryptor().encryptFilename(BaseEncoding.base64Url(), dirIdAndName.name, dirIdAndName.dirId.getBytes(StandardCharsets.UTF_8)) + Constants.CRYPTOMATOR_FILE_SUFFIX;
	}

	public void invalidatePathMapping(CryptoPath cleartextPath) {
		ciphertextDirectories.invalidate(cleartextPath);
	}
	
	public void movePathMapping(CryptoPath cleartextSrc, CryptoPath cleartextDst) {
		CiphertextDirectory cachedValue = ciphertextDirectories.getIfPresent(cleartextSrc);
		if (cachedValue != null) {
			ciphertextDirectories.put(cleartextDst, cachedValue);
			ciphertextDirectories.invalidate(cleartextSrc);
		}
	}

	public CiphertextDirectory getCiphertextDir(CryptoPath cleartextPath) throws IOException {
		assert cleartextPath.isAbsolute();
		CryptoPath parentPath = cleartextPath.getParent();
		if (parentPath == null) {
			return rootDirectory;
		} else {
			try {
				return ciphertextDirectories.get(cleartextPath, () -> {
					Path dirIdFile = getCiphertextFilePath(cleartextPath).getDirFilePath();
					return resolveDirectory(dirIdFile);
				});
			} catch (ExecutionException e) {
				Throwables.throwIfInstanceOf(e.getCause(), IOException.class);
				throw new IOException("Unexpected exception", e);
			}
		}
	}

	public CiphertextDirectory resolveDirectory(Path directoryFile) throws IOException {
		String dirId = dirIdProvider.load(directoryFile);
		return resolveDirectory(dirId);
	}

	private CiphertextDirectory resolveDirectory(String dirId) {
		String dirHash = cryptor.fileNameCryptor().hashDirectoryId(dirId);
		Path dirPath = dataRoot.resolve(dirHash.substring(0, 2)).resolve(dirHash.substring(2));
		return new CiphertextDirectory(dirId, dirPath);
	}

	public static class CiphertextDirectory {
		public final String dirId;
		public final Path path;

		public CiphertextDirectory(String dirId, Path path) {
			this.dirId = Objects.requireNonNull(dirId);
			this.path = Objects.requireNonNull(path);
		}

		@Override
		public int hashCode() {
			return Objects.hash(dirId, path);
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			} else if (obj instanceof CiphertextDirectory other) {
				return this.dirId.equals(other.dirId) && this.path.equals(other.path);
			} else {
				return false;
			}
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
			} else if (obj instanceof DirIdAndName other) {
				return this.dirId.equals(other.dirId) && this.name.equals(other.name);
			} else {
				return false;
			}
		}
	}

}
