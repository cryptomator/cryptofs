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

abstract class AbstractCryptoFileAttributeView<T extends BasicFileAttributeView> implements BasicFileAttributeView {

	protected final Path ciphertextPath;
	protected final CryptoFileAttributeProvider fileAttributeProvider;
	protected final T delegate;

	public AbstractCryptoFileAttributeView(Path ciphertextPath, CryptoFileAttributeProvider fileAttributeProvider, Class<T> delegateType) {
		this.ciphertextPath = ciphertextPath;
		this.fileAttributeProvider = fileAttributeProvider;
		this.delegate = Files.getFileAttributeView(ciphertextPath, delegateType);
	}

	@Override
	public String name() {
		return delegate.name();
	}

	@Override
	public BasicFileAttributes readAttributes() throws IOException {
		return fileAttributeProvider.readAttributes(ciphertextPath, BasicFileAttributes.class);
	}

	@Override
	public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime, FileTime createTime) throws IOException {
		delegate.setTimes(lastModifiedTime, lastAccessTime, createTime);
	}

}
