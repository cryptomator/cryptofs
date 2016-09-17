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

@PerFileSystem
class CryptoPathMapper {

	private static final String ROOT_DIR_ID = "";

	private final Cryptor cryptor;
	private final Path dataRoot;
	private final DirectoryIdProvider dirIdProvider;
	private final LongFileNameProvider longFileNameProvider;

	@Inject
	public CryptoPathMapper(@PathToVault Path pathToVault, Cryptor cryptor, DirectoryIdProvider dirIdProvider, LongFileNameProvider longFileNameProvider) {
		this.dataRoot = pathToVault.resolve(DATA_DIR_NAME);
		this.cryptor = cryptor;
		this.dirIdProvider = dirIdProvider;
		this.longFileNameProvider = longFileNameProvider;
	}

	public enum CiphertextFileType {
		FILE, DIRECTORY
	};

	public Path getCiphertextFilePath(CryptoPath cleartextPath, CiphertextFileType fileType) throws IOException {
		if (cleartextPath.getNameCount() == 0) {
			throw new IllegalArgumentException("Invalid file path " + cleartextPath);
		}
		Directory dir = getCiphertextDir(cleartextPath.getParent());
		String cleartextName = cleartextPath.getFileName().toString();
		String ciphertextName = getCiphertextFileName(dir.dirId, cleartextName, fileType);
		if (ciphertextName.length() >= Constants.NAME_SHORTENING_THRESHOLD) {
			ciphertextName = longFileNameProvider.deflate(ciphertextName);
		}
		return dir.path.resolve(ciphertextName);
	}

	private String getCiphertextFileName(String dirId, String cleartextName, CiphertextFileType fileType) {
		// TODO overheadhunter: cache ciphertext names
		String ciphertextName = cryptor.fileNameCryptor().encryptFilename(cleartextName, dirId.getBytes(StandardCharsets.UTF_8));
		switch (fileType) {
		case DIRECTORY:
			return DIR_PREFIX + ciphertextName;
		default:
			return ciphertextName;
		}
	}

	public Path getCiphertextDirPath(CryptoPath cleartextPath) throws IOException {
		return getCiphertextDir(cleartextPath).path;
	}

	public Directory getCiphertextDir(CryptoPath cleartextPath) throws IOException {
		assert cleartextPath.isAbsolute();
		if (cleartextPath.getNameCount() == 0) {
			return new Directory(ROOT_DIR_ID, resolveDirectory(ROOT_DIR_ID));
		} else {
			Directory parent = getCiphertextDir(cleartextPath.getParent());
			String cleartextName = cleartextPath.getFileName().toString();
			String ciphertextName = getCiphertextFileName(parent.dirId, cleartextName, CiphertextFileType.DIRECTORY);
			String dirId = dirIdProvider.load(parent.path.resolve(ciphertextName));
			return new Directory(dirId, resolveDirectory(dirId));
		}
	}

	private Path resolveDirectory(String dirId) {
		// TODO overheadhunter: cache hashes
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
