/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.nio.file.FileStore;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.Collection;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

public class CryptoFileStore extends DelegatingFileStore {

	private static final Map<String, Class<? extends FileAttributeView>> SUPPORTED_ATTRVIEW_NAMES = ImmutableMap.of( //
			"basic", BasicFileAttributeView.class, //
			"owner", FileOwnerAttributeView.class, //
			"posix", PosixFileAttributeView.class, //
			"dos", DosFileAttributeView.class);
	private static final Collection<Class<?>> SUPPORTED_ATTRVIEW_CLASSES = ImmutableSet.of(PosixFileAttributeView.class, DosFileAttributeView.class);

	public CryptoFileStore(FileStore delegate) {
		super(delegate);
	}

	@Override
	public boolean supportsFileAttributeView(Class<? extends FileAttributeView> type) {
		for (Class<?> clazz : SUPPORTED_ATTRVIEW_CLASSES) {
			if (type.isAssignableFrom(clazz)) {
				return super.supportsFileAttributeView(type);
			}
		}
		return false;
	}

	@Override
	public boolean supportsFileAttributeView(String name) {
		Class<? extends FileAttributeView> type = SUPPORTED_ATTRVIEW_NAMES.get(name);
		if (type == null) {
			return false;
		} else {
			return supportsFileAttributeView(type);
		}
	}

}
