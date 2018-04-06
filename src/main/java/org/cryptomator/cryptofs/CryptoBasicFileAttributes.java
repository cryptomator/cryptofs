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
import java.util.Optional;

import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;

class CryptoBasicFileAttributes implements DelegatingBasicFileAttributes {

	private final BasicFileAttributes delegate;
	protected final Path ciphertextPath;
	private final Cryptor cryptor;
	private final Optional<Long> sizeAccordingToOpenChannel;

	public CryptoBasicFileAttributes(BasicFileAttributes delegate, Path ciphertextPath, Cryptor cryptor, Optional<Long> sizeAccordingToOpenChannel) {
		this.delegate = delegate;
		this.ciphertextPath = ciphertextPath;
		this.cryptor = cryptor;
		this.sizeAccordingToOpenChannel = sizeAccordingToOpenChannel;
	}

	@Override
	public BasicFileAttributes getDelegate() {
		return delegate;
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
		if (isDirectory()) {
			return getDelegate().size();
		} else if (isOther()) {
			return -1l;
		} else if (isSymbolicLink()) {
			return -1l;
		} else if (sizeAccordingToOpenChannel.isPresent()) {
			return sizeAccordingToOpenChannel.get();
		} else {
			return Cryptors.cleartextSize(getDelegate().size() - cryptor.fileHeaderCryptor().headerSize(), cryptor);
		}
	}

}
