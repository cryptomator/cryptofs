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
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

import com.google.common.collect.Sets;
import org.cryptomator.cryptolib.api.Cryptor;

import static java.nio.file.attribute.PosixFilePermission.GROUP_READ;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;

class CryptoPosixFileAttributes extends CryptoBasicFileAttributes implements DelegatingPosixFileAttributes {

	private static final Set<PosixFilePermission> ALL_READ = EnumSet.of(OWNER_READ, GROUP_READ, OTHERS_READ);

	private final PosixFileAttributes delegate;

	public CryptoPosixFileAttributes(PosixFileAttributes delegate, Path ciphertextPath, Cryptor cryptor, Optional<OpenCryptoFile> openCryptoFile, boolean readonly) {
		super(delegate, ciphertextPath, cryptor, openCryptoFile, readonly);
		this.delegate = delegate;
	}

	@Override
	public PosixFileAttributes getDelegate() {
		return delegate;
	}

	@Override
	public Set<PosixFilePermission> permissions() {
		Set<PosixFilePermission> delegatePermissions = delegate.permissions();
		if (readonly) {
			return Sets.intersection(delegatePermissions, ALL_READ);
		} else {
			return delegatePermissions;
		}
	}
}
