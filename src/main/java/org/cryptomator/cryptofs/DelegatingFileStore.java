/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileStoreAttributeView;
import java.util.Objects;

class DelegatingFileStore extends FileStore {

	private final FileStore delegate;

	public DelegatingFileStore(FileStore delegate) {
		this.delegate = Objects.requireNonNull(delegate);
	}

	@Override
	public String name() {
		return type() + "_" + delegate.name();
	}

	@Override
	public String type() {
		return getClass().getSimpleName();
	}

	@Override
	public boolean isReadOnly() {
		return delegate.isReadOnly();
	}

	@Override
	public long getTotalSpace() throws IOException {
		return delegate.getTotalSpace();
	}

	@Override
	public long getUsableSpace() throws IOException {
		return delegate.getUsableSpace();
	}

	@Override
	public long getUnallocatedSpace() throws IOException {
		return delegate.getUnallocatedSpace();
	}

	@Override
	public boolean supportsFileAttributeView(Class<? extends FileAttributeView> type) {
		return delegate.supportsFileAttributeView(type);
	}

	@Override
	public boolean supportsFileAttributeView(String name) {
		return delegate.supportsFileAttributeView(name);
	}

	@Override
	public <V extends FileStoreAttributeView> V getFileStoreAttributeView(Class<V> type) {
		return null; // no attribute view available.
	}

	@Override
	public Object getAttribute(String attribute) throws IOException {
		throw new UnsupportedOperationException();
	}

}
