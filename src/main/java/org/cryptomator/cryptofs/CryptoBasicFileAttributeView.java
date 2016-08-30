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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

class CryptoBasicFileAttributeView implements BasicFileAttributeView {

	protected final Path ciphertextPath;
	protected final CryptoFileAttributeProvider fileAttributeProvider;

	public CryptoBasicFileAttributeView(Path ciphertextPath, CryptoFileAttributeProvider fileAttributeProvider) {
		this.ciphertextPath = ciphertextPath;
		this.fileAttributeProvider = fileAttributeProvider;
	}

	@Override
	public String name() {
		return "basic";
	}

	@Override
	public BasicFileAttributes readAttributes() throws IOException {
		return fileAttributeProvider.readAttributes(ciphertextPath, BasicFileAttributes.class);
	}

	@Override
	public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime, FileTime createTime) throws IOException {
		Files.getFileAttributeView(ciphertextPath, BasicFileAttributeView.class).setTimes(lastModifiedTime, lastAccessTime, createTime);
	}

}
