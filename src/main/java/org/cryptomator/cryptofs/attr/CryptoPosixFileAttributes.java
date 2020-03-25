/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import com.google.common.collect.Sets;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;
import java.nio.file.Path;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

import static java.nio.file.attribute.PosixFilePermission.GROUP_WRITE;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;

@AttributeScoped
class CryptoPosixFileAttributes extends CryptoBasicFileAttributes implements PosixFileAttributes {

	private static final Set<PosixFilePermission> ALL_WRITE = EnumSet.of(OWNER_WRITE, GROUP_WRITE, OTHERS_WRITE);

	private final UserPrincipal owner;
	private final GroupPrincipal group;
	private final Set<PosixFilePermission> permissions;

	@Inject
	public CryptoPosixFileAttributes(PosixFileAttributes delegate, CiphertextFileType ciphertextFileType, Path ciphertextPath, Cryptor cryptor, Optional<OpenCryptoFile> openCryptoFile, CryptoFileSystemProperties fileSystemProperties) {
		super(delegate, ciphertextFileType, ciphertextPath, cryptor, openCryptoFile);
		this.owner = delegate.owner();
		this.group = delegate.group();
		if (fileSystemProperties.readonly()) {
			this.permissions = Sets.difference(delegate.permissions(), ALL_WRITE);
		} else {
			this.permissions = delegate.permissions();
		}
	}

	@Override
	public UserPrincipal owner() {
		return owner;
	}

	@Override
	public GroupPrincipal group() {
		return group;
	}

	@Override
	public Set<PosixFilePermission> permissions() {
		return permissions;
	}
}
