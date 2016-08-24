/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

interface DelegatingPosixFileAttributes extends DelegatingBasicFileAttributes, PosixFileAttributes {

	@Override
	PosixFileAttributes getDelegate();

	@Override
	default UserPrincipal owner() {
		return getDelegate().owner();
	}

	@Override
	default GroupPrincipal group() {
		return getDelegate().group();
	}

	@Override
	default Set<PosixFilePermission> permissions() {
		return getDelegate().permissions();
	}

}
