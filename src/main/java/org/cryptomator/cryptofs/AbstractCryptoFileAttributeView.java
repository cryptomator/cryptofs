/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileAttributeView;
import java.util.Optional;

abstract class AbstractCryptoFileAttributeView implements FileAttributeView {

	protected final CryptoPath cleartextPath;
	private final CryptoPathMapper pathMapper;
	private final OpenCryptoFiles openCryptoFiles;

	public AbstractCryptoFileAttributeView(CryptoPath cleartextPath, CryptoPathMapper pathMapper, OpenCryptoFiles openCryptoFiles) {
		this.cleartextPath = cleartextPath;
		this.pathMapper = pathMapper;
		this.openCryptoFiles = openCryptoFiles;
	}

	protected <T extends FileAttributeView> T getCiphertextAttributeView(Class<T> delegateType) throws IOException {
		Path ciphertextPath = getCiphertextPath();
		return ciphertextPath.getFileSystem().provider().getFileAttributeView(ciphertextPath, delegateType);
	}

	protected Path getCiphertextPath() throws IOException {
		CryptoPathMapper.CiphertextFileType type = pathMapper.getCiphertextFileType(cleartextPath);
		switch (type) {
			case DIRECTORY:
				return pathMapper.getCiphertextDirPath(cleartextPath);
			default:
				return pathMapper.getCiphertextFilePath(cleartextPath, type);
		}
	}

	protected Optional<OpenCryptoFile> getOpenCryptoFile() throws IOException {
		Path ciphertextPath = getCiphertextPath();
		return openCryptoFiles.get(ciphertextPath);
	}

}
