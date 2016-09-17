/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.Constants.DATA_DIR_NAME;
import static org.cryptomator.cryptofs.Constants.DIR_PREFIX;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import javax.inject.Inject;

import org.cryptomator.cryptolib.api.Cryptor;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

@PerFileSystem
class CryptoPathMapper {

	private static final String ROOT_DIR_ID = "";
	private static final int MAX_CACHED_DIR_PATHS = 1000;

	private final Cryptor cryptor;
	private final Path dataRoot;
	private final DirectoryIdProvider dirIdProvider;
	private final LongFileNameProvider longFileNameProvider;
	private final LoadingCache<String, Path> directoryPathCache;

	@Inject
	public CryptoPathMapper(@PathToVault Path pathToVault, Cryptor cryptor, DirectoryIdProvider dirIdProvider, LongFileNameProvider longFileNameProvider) {
		this.dataRoot = pathToVault.resolve(DATA_DIR_NAME);
		this.cryptor = cryptor;
		this.dirIdProvider = dirIdProvider;
		this.longFileNameProvider = longFileNameProvider;
		this.directoryPathCache = CacheBuilder.newBuilder().maximumSize(MAX_CACHED_DIR_PATHS).build(CacheLoader.from(this::resolveDirectory));
	}

	public enum CiphertextFileType {
		FILE, DIRECTORY
	};

	public Path getCiphertextFilePath(CryptoPath cleartextPath, CiphertextFileType fileType) throws IOException {
		if (cleartextPath.getNameCount() == 0) {
			throw new IllegalArgumentException("Invalid file path " + cleartextPath);
		}
		CryptoPath dirPath = cleartextPath.getParent();
		assert dirPath != null : "namecount > 0";
		Directory dir = getCiphertextDir(dirPath);
		String cleartextName = cleartextPath.getFileName().toString();
		String ciphertextName = getCiphertextFileName(dir.dirId, cleartextName, fileType);
		return dir.path.resolve(ciphertextName);
	}

	private String getCiphertextFileName(String dirId, String cleartextName, CiphertextFileType fileType) throws IOException {
		// TODO overheadhunter: cache ciphertext names
		String prefix = (fileType == CiphertextFileType.DIRECTORY) ? DIR_PREFIX : "";
		String ciphertextName = prefix + cryptor.fileNameCryptor().encryptFilename(cleartextName, dirId.getBytes(StandardCharsets.UTF_8));
		if (ciphertextName.length() >= Constants.NAME_SHORTENING_THRESHOLD) {
			return longFileNameProvider.deflate(ciphertextName);
		} else {
			return ciphertextName;
		}
	}

	public Path getCiphertextDirPath(CryptoPath cleartextPath) throws IOException {
		return getCiphertextDir(cleartextPath).path;
	}

	public Directory getCiphertextDir(CryptoPath cleartextPath) throws IOException {
		assert cleartextPath.isAbsolute();
		if (cleartextPath.getNameCount() == 0) {
			return new Directory(ROOT_DIR_ID, directoryPathCache.getUnchecked(ROOT_DIR_ID));
		} else {
			CryptoPath parentPath = cleartextPath.getParent();
			assert parentPath != null : "namecount > 0";
			Directory parent = getCiphertextDir(parentPath);
			String cleartextName = cleartextPath.getFileName().toString();
			String ciphertextName = getCiphertextFileName(parent.dirId, cleartextName, CiphertextFileType.DIRECTORY);
			String dirId = dirIdProvider.load(parent.path.resolve(ciphertextName));
			return new Directory(dirId, directoryPathCache.getUnchecked(dirId));
		}
	}

	private Path resolveDirectory(String dirId) {
		String dirHash = cryptor.fileNameCryptor().hashDirectoryId(dirId);
		return dataRoot.resolve(dirHash.substring(0, 2)).resolve(dirHash.substring(2));
	}

	public static class Directory {
		public final String dirId;
		public final Path path;

		public Directory(String dirId, Path path) {
			this.dirId = dirId;
			this.path = path;
		}
	}

}
