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

import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;

@AttributeScoped
class CryptoDosFileAttributes extends CryptoBasicFileAttributes implements DosFileAttributes {

	private final boolean readonlyFileSystem;
	private final DosFileAttributes delegate;

	@Inject
	public CryptoDosFileAttributes(DosFileAttributes delegate, CiphertextFileType ciphertextFileType, Path ciphertextPath, Cryptor cryptor, Optional<OpenCryptoFile> openCryptoFile, CryptoFileSystemProperties fileSystemProperties) {
		super(delegate, ciphertextFileType, ciphertextPath, cryptor, openCryptoFile);
		this.readonlyFileSystem = fileSystemProperties.readonly();
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
