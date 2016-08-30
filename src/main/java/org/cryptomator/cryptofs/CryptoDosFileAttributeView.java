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
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.DosFileAttributes;

class CryptoDosFileAttributeView extends CryptoBasicFileAttributeView implements DosFileAttributeView {

	public CryptoDosFileAttributeView(Path ciphertextPath, CryptoFileAttributeProvider fileAttributeProvider) {
		super(ciphertextPath, fileAttributeProvider);
	}

	@Override
	public String name() {
		return "dos";
	}

	@Override
	public DosFileAttributes readAttributes() throws IOException {
		return fileAttributeProvider.readAttributes(ciphertextPath, DosFileAttributes.class);
	}

	@Override
	public void setReadOnly(boolean value) throws IOException {
		Files.getFileAttributeView(ciphertextPath, DosFileAttributeView.class).setReadOnly(value);
	}

	@Override
	public void setHidden(boolean value) throws IOException {
		Files.getFileAttributeView(ciphertextPath, DosFileAttributeView.class).setHidden(value);
	}

	@Override
	public void setSystem(boolean value) throws IOException {
		Files.getFileAttributeView(ciphertextPath, DosFileAttributeView.class).setSystem(value);
	}

	@Override
	public void setArchive(boolean value) throws IOException {
		Files.getFileAttributeView(ciphertextPath, DosFileAttributeView.class).setArchive(value);
	}

}
