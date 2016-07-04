/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.nio.file.attribute.DosFileAttributes;

class DelegatingDosFileAttributes extends DelegatingBasicFileAttributes implements DosFileAttributes {

	private final DosFileAttributes delegate;

	public DelegatingDosFileAttributes(DosFileAttributes delegate) {
		super(delegate);
		this.delegate = delegate;
	}

	@Override
	public boolean isReadOnly() {
		return delegate.isReadOnly();
	}

	@Override
	public boolean isHidden() {
		return delegate.isHidden();
	}

	@Override
	public boolean isArchive() {
		return delegate.isArchive();
	}

	@Override
	public boolean isSystem() {
		return delegate.isSystem();
	}

}
