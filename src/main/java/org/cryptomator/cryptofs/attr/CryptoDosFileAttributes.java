/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptolib.api.Cryptor;

import java.nio.file.Path;
import java.nio.file.attribute.DosFileAttributes;
import java.util.Optional;

final class CryptoDosFileAttributes extends CryptoBasicFileAttributes implements DosFileAttributes {

	private final boolean isReadOnly;
	private final boolean isArchive;
	private final boolean isHidden;
	private final boolean isSystem;

	public CryptoDosFileAttributes(DosFileAttributes delegate, //
								   CiphertextFileType ciphertextFileType, //
								   Path ciphertextPath, //
								   Cryptor cryptor, //
								   Optional<OpenCryptoFile> openCryptoFile, //
								   CryptoFileSystemProperties fileSystemProperties) {
		super(delegate, ciphertextFileType, ciphertextPath, cryptor, openCryptoFile);
		this.isReadOnly = fileSystemProperties.readonly() || delegate.isReadOnly();
		this.isHidden = delegate.isHidden();
		this.isArchive = delegate.isArchive();
		this.isSystem = delegate.isSystem();
	}

	@Override
	public boolean isReadOnly() {
		return isReadOnly;
	}

	@Override
	public boolean isHidden() {
		return isHidden;
	}

	@Override
	public boolean isArchive() {
		return isArchive;
	}

	@Override
	public boolean isSystem() {
		return isSystem;
	}
}
