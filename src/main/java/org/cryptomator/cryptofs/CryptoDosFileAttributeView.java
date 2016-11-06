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
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.DosFileAttributes;

class CryptoDosFileAttributeView extends AbstractCryptoFileAttributeView<DosFileAttributes, DosFileAttributeView> implements DosFileAttributeView {

	public CryptoDosFileAttributeView(Path ciphertextPath, CryptoFileAttributeProvider fileAttributeProvider) throws UnsupportedFileAttributeViewException {
		super(ciphertextPath, fileAttributeProvider, DosFileAttributes.class, DosFileAttributeView.class);
	}

	@Override
	public String name() {
		return "dos";
	}

	@Override
	public void setReadOnly(boolean value) throws IOException {
		delegate.setReadOnly(value);
	}

	@Override
	public void setHidden(boolean value) throws IOException {
		delegate.setHidden(value);
	}

	@Override
	public void setSystem(boolean value) throws IOException {
		delegate.setSystem(value);
	}

	@Override
	public void setArchive(boolean value) throws IOException {
		delegate.setArchive(value);
	}

}
