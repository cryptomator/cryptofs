/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.cryptomator.cryptofs.ReadonlyFlag;
import org.cryptomator.cryptofs.Symlinks;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.DosFileAttributes;

@AttributeViewScoped
class CryptoDosFileAttributeView extends CryptoBasicFileAttributeView implements DosFileAttributeView {

	@Inject
	public CryptoDosFileAttributeView(CryptoPath cleartextPath, CryptoPathMapper pathMapper, LinkOption[] linkOptions, Symlinks symlinks, OpenCryptoFiles openCryptoFiles, AttributeProvider fileAttributeProvider, ReadonlyFlag readonlyFlag) {
		super(cleartextPath, pathMapper, linkOptions, symlinks, openCryptoFiles, fileAttributeProvider, readonlyFlag);
	}

	@Override
	public String name() {
		return "dos";
	}

	@Override
	public DosFileAttributes readAttributes() throws IOException {
		return fileAttributeProvider.readAttributes(cleartextPath, DosFileAttributes.class, linkOptions);
	}

	@Override
	public void setReadOnly(boolean value) throws IOException {
		readonlyFlag.assertWritable();
		getCiphertextAttributeView(DosFileAttributeView.class).setReadOnly(value);
	}

	@Override
	public void setHidden(boolean value) throws IOException {
		readonlyFlag.assertWritable();
		getCiphertextAttributeView(DosFileAttributeView.class).setHidden(value);
	}

	@Override
	public void setSystem(boolean value) throws IOException {
		readonlyFlag.assertWritable();
		getCiphertextAttributeView(DosFileAttributeView.class).setSystem(value);
	}

	@Override
	public void setArchive(boolean value) throws IOException {
		readonlyFlag.assertWritable();
		getCiphertextAttributeView(DosFileAttributeView.class).setArchive(value);
	}

}
