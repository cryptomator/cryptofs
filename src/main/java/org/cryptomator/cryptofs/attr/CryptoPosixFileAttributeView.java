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
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

@AttributeViewScoped
class CryptoPosixFileAttributeView extends CryptoBasicFileAttributeView implements PosixFileAttributeView {

	@Inject
	public CryptoPosixFileAttributeView(CryptoPath cleartextPath, CryptoPathMapper pathMapper, LinkOption[] linkOptions, Symlinks symlinks, OpenCryptoFiles openCryptoFiles, AttributeProvider fileAttributeProvider, ReadonlyFlag readonlyFlag) {
		super(cleartextPath, pathMapper, linkOptions, symlinks, openCryptoFiles, fileAttributeProvider, readonlyFlag);
	}

	@Override
	public String name() {
		return "posix";
	}

	@Override
	public PosixFileAttributes readAttributes() throws IOException {
		return fileAttributeProvider.readAttributes(cleartextPath, PosixFileAttributes.class, linkOptions);
	}

	@Override
	public UserPrincipal getOwner() throws IOException {
		return getCiphertextAttributeView(PosixFileAttributeView.class).getOwner();
	}

	@Override
	public void setOwner(UserPrincipal owner) throws IOException {
		readonlyFlag.assertWritable();
		getCiphertextAttributeView(PosixFileAttributeView.class).setOwner(owner);
	}

	@Override
	public void setPermissions(Set<PosixFilePermission> perms) throws IOException {
		readonlyFlag.assertWritable();
		getCiphertextAttributeView(PosixFileAttributeView.class).setPermissions(perms);
	}

	@Override
	public void setGroup(GroupPrincipal group) throws IOException {
		readonlyFlag.assertWritable();
		getCiphertextAttributeView(PosixFileAttributeView.class).setGroup(group);
	}

}
