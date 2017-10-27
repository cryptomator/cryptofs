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
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

abstract class AbstractCryptoFileAttributeView<S extends BasicFileAttributes, T extends BasicFileAttributeView> implements BasicFileAttributeView {

	protected final Path ciphertextPath;
	protected final CryptoFileAttributeProvider fileAttributeProvider;
	protected final T delegate;
	private final Class<S> attributesType;
	private final ReadonlyFlag readonlyFlag;

	public AbstractCryptoFileAttributeView(Path ciphertextPath, CryptoFileAttributeProvider fileAttributeProvider, ReadonlyFlag readonlyFlag, Class<S> attributesType, Class<T> delegateType)
			throws UnsupportedFileAttributeViewException {
		this.ciphertextPath = ciphertextPath;
		this.fileAttributeProvider = fileAttributeProvider;
		this.readonlyFlag = readonlyFlag;
		this.attributesType = attributesType;
		this.delegate = ciphertextPath.getFileSystem().provider().getFileAttributeView(ciphertextPath, delegateType);
		if (delegate == null) {
			throw new UnsupportedFileAttributeViewException();
		}
	}

	@Override
	public final S readAttributes() throws IOException {
		return fileAttributeProvider.readAttributes(ciphertextPath, attributesType);
	}

	@Override
	public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime, FileTime createTime) throws IOException {
		readonlyFlag.assertWritable();
		delegate.setTimes(lastModifiedTime, lastAccessTime, createTime);
	}

}
