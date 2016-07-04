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
import java.io.UncheckedIOException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;
import java.util.Set;

class CryptoFileSystem extends BasicFileSystem {

	private final CryptoFileSystemProvider provider;
	private final Path pathToVault;

	CryptoFileSystem(CryptoFileSystemProvider provider, Path pathToVault) {
		this.provider = provider;
		this.pathToVault = pathToVault;
	}

	@Override
	public FileSystemProvider provider() {
		return provider;
	}

	@Override
	public void close() throws IOException {
		// TODO destroy cryptor
		provider.fileSystems.remove(pathToVault);
	}

	@Override
	public boolean isOpen() {
		return provider.fileSystems.containsValue(this);
	}

	@Override
	public FileStore getFileStore() {
		try {
			FileStore fileStoreForPathToVault = Files.getFileStore(pathToVault);
			// TODO do we really need to a delegate? If we don't intercept any methods, just return the original file store.
			return new DelegatingFileStore(fileStoreForPathToVault);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	@Override
	public Set<String> supportedFileAttributeViews() {
		// essentially we support posix or dos, if we need to intercept the attribute views. otherwise we support just anything
		return pathToVault.getFileSystem().supportedFileAttributeViews();
	}

}
