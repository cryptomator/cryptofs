/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.attr.AttributeViewType;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileStoreAttributeView;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@CryptoFileSystemScoped
class CryptoFileStore extends FileStore {

	static final long DEFAULT_TOTAL_SPACE = 10_000_000_000l; // 10 GiB
	static final long DEFAULT_USABLE_SPACE = 10_000_000_000l;
	static final long DEFAULT_UNALLOCATED_SPACE = 10_000_000_000l;

	private final Optional<FileStore> delegate;
	private final ReadonlyFlag readonlyFlag;
	private final Set<AttributeViewType> supportedFileAttributeViewTypes;

	@Inject
	public CryptoFileStore(Optional<FileStore> delegate, ReadonlyFlag readonlyFlag) {
		this.delegate = delegate;
		this.readonlyFlag = readonlyFlag;
		this.supportedFileAttributeViewTypes = determineSupportedFileAttributeViewTypes();
	}

	private Set<AttributeViewType> determineSupportedFileAttributeViewTypes() {
		return Arrays.stream(AttributeViewType.values()).filter(t -> this.supportsFileAttributeView(t.getType())).collect(Collectors.toSet());
	}

	Set<AttributeViewType> supportedFileAttributeViewTypes() {
		return supportedFileAttributeViewTypes;
	}

	/* FileStore API: */

	@Override
	public String name() {
		return type();
	}

	@Override
	public String type() {
		return getClass().getSimpleName();
	}

	@Override
	public boolean isReadOnly() {
		return readonlyFlag.isSet() || delegate.map(FileStore::isReadOnly).orElse(false);
	}

	@Override
	public long getTotalSpace() throws IOException {
		return delegate.isPresent() ? delegate.get().getTotalSpace() : DEFAULT_TOTAL_SPACE;
	}

	@Override
	public long getUsableSpace() throws IOException {
		return delegate.isPresent() ? delegate.get().getUsableSpace() : DEFAULT_USABLE_SPACE;
	}

	@Override
	public long getUnallocatedSpace() throws IOException {
		return delegate.isPresent() ? delegate.get().getUnallocatedSpace() : DEFAULT_UNALLOCATED_SPACE;
	}

	@Override
	public boolean supportsFileAttributeView(Class<? extends FileAttributeView> type) {
		if (delegate.isPresent()) {
			return delegate.get().supportsFileAttributeView(type) && AttributeViewType.getByType(type).isPresent();
		} else {
			return AttributeViewType.BASIC.getType().equals(type);
		}
	}

	@Override
	public boolean supportsFileAttributeView(String name) {
		if (delegate.isPresent()) {
			return delegate.get().supportsFileAttributeView(name) && AttributeViewType.getByName(name).isPresent();
		} else {
			return AttributeViewType.BASIC.getViewName().equals(name);
		}
	}

	@Override
	public <V extends FileStoreAttributeView> V getFileStoreAttributeView(Class<V> type) {
		return null; // as per contract
	}

	@Override
	public Object getAttribute(String attribute) {
		throw new UnsupportedOperationException(); // as per contract
	}

}
