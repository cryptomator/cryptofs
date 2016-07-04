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

class DelegatingPosixFileAttributes extends DelegatingBasicFileAttributes implements PosixFileAttributes {

	private final PosixFileAttributes delegate;

	public DelegatingPosixFileAttributes(PosixFileAttributes delegate) {
		super(delegate);
		this.delegate = delegate;
	}

	@Override
	public UserPrincipal owner() {
		return delegate.owner();
	}

	@Override
	public GroupPrincipal group() {
		return delegate.group();
	}

	@Override
	public Set<PosixFilePermission> permissions() {
		return delegate.permissions();
	}

}
