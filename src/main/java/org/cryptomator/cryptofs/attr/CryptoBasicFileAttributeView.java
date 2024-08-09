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
import org.cryptomator.cryptofs.ReadonlyFlag;
import org.cryptomator.cryptofs.Symlinks;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

@AttributeViewScoped
sealed class CryptoBasicFileAttributeView extends AbstractCryptoFileAttributeView implements BasicFileAttributeView
		permits CryptoDosFileAttributeView, CryptoPosixFileAttributeView {

	protected final AttributeProvider fileAttributeProvider;
	protected final ReadonlyFlag readonlyFlag;

	@Inject
	public CryptoBasicFileAttributeView(CryptoPath cleartextPath, CryptoPathMapper pathMapper, LinkOption[] linkOptions, Symlinks symlinks, OpenCryptoFiles openCryptoFiles, AttributeProvider fileAttributeProvider, ReadonlyFlag readonlyFlag) {
		super(cleartextPath, pathMapper, linkOptions, symlinks, openCryptoFiles);
		this.fileAttributeProvider = fileAttributeProvider;
		this.readonlyFlag = readonlyFlag;
	}

	@Override
	public String name() {
		return "basic";
	}

	@Override
	public BasicFileAttributes readAttributes() throws IOException {
		return fileAttributeProvider.readAttributes(cleartextPath, BasicFileAttributes.class, linkOptions);
	}

	@Override
	public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime, FileTime createTime) throws IOException {
		readonlyFlag.assertWritable();
		if (lastModifiedTime != null) {
			getOpenCryptoFile().ifPresent(file -> file.setLastModifiedTime(lastModifiedTime));
		}
		getCiphertextAttributeView(BasicFileAttributeView.class).setTimes(lastModifiedTime, lastAccessTime, createTime);
	}

}
