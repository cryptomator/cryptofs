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
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.UserPrincipal;

class CryptoFileOwnerAttributeView implements FileOwnerAttributeView {

	private final FileOwnerAttributeView delegate;

	public CryptoFileOwnerAttributeView(Path ciphertextPath, CryptoFileAttributeProvider fileAttributeProvider) throws UnsupportedFileAttributeViewException {
		this.delegate = Files.getFileAttributeView(ciphertextPath, FileOwnerAttributeView.class);
		if (delegate == null) {
			throw new UnsupportedFileAttributeViewException();
		}
	}

	@Override
	public UserPrincipal getOwner() throws IOException {
		return delegate.getOwner();
	}

	@Override
	public void setOwner(UserPrincipal owner) throws IOException {
		delegate.setOwner(owner);
	}

	@Override
	public String name() {
		return "owner";
	}

}
