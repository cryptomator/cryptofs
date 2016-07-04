/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Objects;

abstract class DelegatingBasicFileAttributes implements BasicFileAttributes {

	private final BasicFileAttributes delegate;

	public DelegatingBasicFileAttributes(BasicFileAttributes delegate) {
		this.delegate = Objects.requireNonNull(delegate);
	}

	@Override
	public FileTime lastModifiedTime() {
		return delegate.lastModifiedTime();
	}

	@Override
	public FileTime lastAccessTime() {
		return delegate.lastAccessTime();
	}

	@Override
	public FileTime creationTime() {
		return delegate.creationTime();
	}

	@Override
	public boolean isRegularFile() {
		return delegate.isRegularFile();
	}

	@Override
	public boolean isDirectory() {
		return delegate.isDirectory();
	}

	@Override
	public boolean isSymbolicLink() {
		return delegate.isSymbolicLink();
	}

	@Override
	public boolean isOther() {
		return delegate.isOther();
	}

	@Override
	public long size() {
		return delegate.size();
	}

	@Override
	public Object fileKey() {
		return delegate.fileKey();
	}

}
