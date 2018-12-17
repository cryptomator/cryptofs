/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

@PerAttributeView
class CryptoPosixFileAttributeView extends CryptoBasicFileAttributeView implements PosixFileAttributeView {

	@Inject
	public CryptoPosixFileAttributeView(CryptoPath cleartextPath, CryptoPathMapper pathMapper, OpenCryptoFiles openCryptoFiles, CryptoFileAttributeProvider fileAttributeProvider, ReadonlyFlag readonlyFlag) {
		super(cleartextPath, pathMapper, openCryptoFiles, fileAttributeProvider, readonlyFlag);
	}

	@Override
	public String name() {
		return "posix";
	}

	@Override
	public PosixFileAttributes readAttributes() throws IOException {
		Path ciphertextPath = getCiphertextPath();
		return fileAttributeProvider.readAttributes(ciphertextPath, PosixFileAttributes.class);
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
