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
import java.io.UncheckedIOException;
import java.nio.file.FileStore;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttributeView;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@CryptoFileSystemScoped
class CryptoFileStore extends DelegatingFileStore {

	private final ReadonlyFlag readonlyFlag;
	private final Set<AttributeViewType> supportedFileAttributeViewTypes;

	@Inject
	public CryptoFileStore(@PathToVault Path pathToVault, ReadonlyFlag readonlyFlag) {
		super(getFileStore(pathToVault));
		this.readonlyFlag = readonlyFlag;
		this.supportedFileAttributeViewTypes = Arrays.stream(AttributeViewType.values()).filter(this::supportsViewType).collect(Collectors.toSet());
	}

	private static FileStore getFileStore(Path path) {
		try {
			return path.getFileSystem().provider().getFileStore(path);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private boolean supportsViewType(AttributeViewType viewType) {
		return super.supportsFileAttributeView(viewType.getType());
	}

	@Override
	public boolean isReadOnly() {
		return readonlyFlag.isSet();
	}

	@Override
	public boolean supportsFileAttributeView(Class<? extends FileAttributeView> type) {
		return AttributeViewType.getByType(type).filter(this::supportsViewType).isPresent();
	}

	@Override
	public boolean supportsFileAttributeView(String name) {
		return AttributeViewType.getByName(name).filter(this::supportsViewType).isPresent();
	}

	Set<AttributeViewType> supportedFileAttributeViewTypes() {
		return supportedFileAttributeViewTypes;
	}

}
