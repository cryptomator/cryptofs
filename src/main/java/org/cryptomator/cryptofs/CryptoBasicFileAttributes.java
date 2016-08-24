/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;

class CryptoBasicFileAttributes implements DelegatingBasicFileAttributes {

	private final BasicFileAttributes delegate;
	protected final Path ciphertextPath;
	private final Cryptor cryptor;

	public CryptoBasicFileAttributes(BasicFileAttributes delegate, Path ciphertextPath, Cryptor cryptor) {
		this.delegate = delegate;
		this.ciphertextPath = ciphertextPath;
		this.cryptor = cryptor;
	}

	@Override
	public BasicFileAttributes getDelegate() {
		return delegate;
	}

	@Override
	public boolean isRegularFile() {
		return getDelegate().isRegularFile() && !isDirectory();
	}

	@Override
	public boolean isDirectory() {
		return getDelegate().isRegularFile() && ciphertextPath.getFileName().toString().startsWith(Constants.DIR_PREFIX);
	}

	@Override
	public boolean isOther() {
		return false;
	}

	@Override
	public boolean isSymbolicLink() {
		return false;
	}

	@Override
	public long size() {
		if (isRegularFile()) {
			return Cryptors.cleartextSize(getDelegate().size() - cryptor.fileHeaderCryptor().headerSize(), cryptor);
		} else {
			return -1l;
		}
	}

}
