/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.collect.Sets;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileStore;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@PerFileSystem
class CryptoFileStore extends DelegatingFileStore {

	private static final String VIEW_NAME_BASIC = "basic";
	private static final String VIEW_NAME_OWNER = "owner";
	private static final String VIEW_NAME_POSIX = "posix";
	private static final String VIEW_NAME_DOS = "dos";
	private static final String[] VIEW_NAMES = {VIEW_NAME_BASIC, VIEW_NAME_OWNER, VIEW_NAME_POSIX, VIEW_NAME_DOS};
	private static final Collection<Class<? extends FileAttributeView>> KNOWN_VIEWS = Sets.newHashSet(BasicFileAttributeView.class, FileOwnerAttributeView.class, PosixFileAttributeView.class, DosFileAttributeView.class);

	private final Set<Class<? extends FileAttributeView>> supportedFileAttributeViewTypes;
	private final ReadonlyFlag readonlyFlag;

	@Inject
	public CryptoFileStore(@PathToVault Path pathToVault, ReadonlyFlag readonlyFlag, CryptoFileAttributeViewProvider attributeViewProvider) {
		super(getFileStore(pathToVault));
		this.readonlyFlag = readonlyFlag;
		this.supportedFileAttributeViewTypes = KNOWN_VIEWS.stream().filter(super::supportsFileAttributeView).collect(Collectors.toSet());
	}

	private static FileStore getFileStore(Path path) {
		try {
			return path.getFileSystem().provider().getFileStore(path);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	@Override
	public boolean supportsFileAttributeView(Class<? extends FileAttributeView> type) {
		return supportedFileAttributeViewTypes.stream().filter(type::isAssignableFrom).findAny().isPresent();
	}

	@Override
	public boolean isReadOnly() {
		return readonlyFlag.isSet();
	}

	@Override
	public boolean supportsFileAttributeView(String name) {
		switch (name) {
		case VIEW_NAME_BASIC:
			return supportsFileAttributeView(BasicFileAttributeView.class);
		case VIEW_NAME_OWNER:
			return supportsFileAttributeView(FileOwnerAttributeView.class);
		case VIEW_NAME_POSIX:
			return supportsFileAttributeView(PosixFileAttributeView.class);
		case VIEW_NAME_DOS:
			return supportsFileAttributeView(DosFileAttributeView.class);
		default:
			return false;
		}
	}

	Set<Class<? extends FileAttributeView>> supportedFileAttributeViewTypes() {
		return supportedFileAttributeViewTypes;
	}

	Set<String> supportedFileAttributeViewNames() {
		return Arrays.stream(VIEW_NAMES).filter(this::supportsFileAttributeView).collect(Collectors.toSet());
	}

}
