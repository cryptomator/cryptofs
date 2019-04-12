/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import java.nio.file.Path;
import java.nio.file.attribute.DosFileAttributes;
import java.util.Optional;

import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptolib.api.Cryptor;

class CryptoDosFileAttributes extends CryptoBasicFileAttributes implements DosFileAttributes {

	private final boolean readonlyFileSystem;
	private final DosFileAttributes delegate;

	public CryptoDosFileAttributes(DosFileAttributes delegate, CryptoPathMapper.CiphertextFileType ciphertextFileType, Path ciphertextPath, Cryptor cryptor, Optional<OpenCryptoFile> openCryptoFile, boolean readonlyFileSystem) {
		super(delegate, ciphertextFileType, ciphertextPath, cryptor, openCryptoFile, readonlyFileSystem);
		this.readonlyFileSystem = readonlyFileSystem;
		this.delegate = delegate;
	}

	@Override
	public boolean isReadOnly() {
		return readonlyFileSystem || delegate.isReadOnly();
	}

	@Override
	public boolean isHidden() {
		return delegate.isHidden();
	}

	@Override
	public boolean isArchive() {
		return delegate.isArchive();
	}

	@Override
	public boolean isSystem() {
		return delegate.isSystem();
	}
}
