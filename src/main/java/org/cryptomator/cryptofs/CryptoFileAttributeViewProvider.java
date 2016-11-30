/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

@PerFileSystem
class CryptoFileAttributeViewProvider {

	private final Map<Class<? extends FileAttributeView>, FileAttributeViewProvider<? extends FileAttributeView>> fileAttributeViewProviders = new HashMap<>();
	private final CryptoFileAttributeProvider fileAttributeProvider;

	@Inject
	public CryptoFileAttributeViewProvider(CryptoFileAttributeProvider fileAttributeProvider) {
		fileAttributeViewProviders.put(BasicFileAttributeView.class, CryptoBasicFileAttributeView::new);
		fileAttributeViewProviders.put(PosixFileAttributeView.class, CryptoPosixFileAttributeView::new);
		fileAttributeViewProviders.put(FileOwnerAttributeView.class, (ciphertextPath, ignored) -> new CryptoFileOwnerAttributeView(ciphertextPath));
		fileAttributeViewProviders.put(DosFileAttributeView.class, CryptoDosFileAttributeView::new);
		this.fileAttributeProvider = fileAttributeProvider;
	}

	/**
	 * @param ciphertextPath the path to the file
	 * @param type the Class object corresponding to the file attribute view
	 * @return a file attribute view of the specified type, or <code>null</code> if the attribute view type is not available
	 * @see Files#getFileAttributeView(Path, Class, java.nio.file.LinkOption...)
	 */
	public <A extends FileAttributeView> A getAttributeView(Path ciphertextPath, Class<A> type) {
		if (fileAttributeViewProviders.containsKey(type)) {
			@SuppressWarnings("unchecked")
			FileAttributeViewProvider<A> provider = (FileAttributeViewProvider<A>) fileAttributeViewProviders.get(type);
			try {
				return provider.provide(ciphertextPath, fileAttributeProvider);
			} catch (UnsupportedFileAttributeViewException e) {
				return null;
			}
		} else {
			// requested file attribute view is unsupported / unknown
			return null;
		}
	}

	Set<Class<? extends FileAttributeView>> knownFileAttributeViewTypes() {
		return Collections.unmodifiableSet(fileAttributeViewProviders.keySet());
	}

	@FunctionalInterface
	private static interface FileAttributeViewProvider<A extends FileAttributeView> {
		A provide(Path ciphertextPath, CryptoFileAttributeProvider fileAttributeProvider) throws UnsupportedFileAttributeViewException;
	}

}
