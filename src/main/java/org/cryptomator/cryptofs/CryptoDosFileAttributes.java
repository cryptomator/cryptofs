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
import java.nio.file.attribute.DosFileAttributes;
import java.util.Optional;

import org.cryptomator.cryptolib.api.Cryptor;

class CryptoDosFileAttributes extends CryptoBasicFileAttributes implements DelegatingDosFileAttributes {

	private final DosFileAttributes delegate;

	public CryptoDosFileAttributes(DosFileAttributes delegate, Path ciphertextPath, Cryptor cryptor, Optional<Long> sizeAccordingToOpenChannel) {
		super(delegate, ciphertextPath, cryptor, sizeAccordingToOpenChannel);
		this.delegate = delegate;
	}

	@Override
	public DosFileAttributes getDelegate() {
		return delegate;
	}

}
