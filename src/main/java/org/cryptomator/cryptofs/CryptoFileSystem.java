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
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.StandardCopyOption;
import java.nio.file.spi.FileSystemProvider;
import java.util.Set;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;

class CryptoFileSystem extends BasicFileSystem {

	private final CryptoFileSystemProvider provider;
	private final Path pathToVault;
	private final Path dataRoot;
	private final Cryptor cryptor;
	private final DirectoryIdProvider dirIdProvider;
	private final CryptoPathMapper cryptoPathMapper;
	private final CryptoFileAttributeProvider fileAttributeProvider;
	private final OpenCryptoFiles openCryptoFiles;

	public CryptoFileSystem(CryptoFileSystemProvider provider, CryptorProviderImpl cryptorProvider, Path pathToVault, CharSequence passphrase, boolean readonly)
			throws UnsupportedVaultFormatException, InvalidPassphraseException, UncheckedIOException {
		this.provider = provider;
		this.pathToVault = pathToVault;
		this.dataRoot = pathToVault.resolve(Constants.DATA_DIR_NAME);

		try {
			Path masterKeyPath = pathToVault.resolve(Constants.MASTERKEY_FILE_NAME);
			Path backupKeyPath = pathToVault.resolve(Constants.BACKUPKEY_FILE_NAME);
			if (Files.isRegularFile(masterKeyPath)) {
				byte[] keyFileContents = Files.readAllBytes(masterKeyPath);
				this.cryptor = cryptorProvider.createFromKeyFile(KeyFile.parse(keyFileContents), passphrase, Constants.VAULT_VERSION);
				Files.copy(masterKeyPath, backupKeyPath, StandardCopyOption.REPLACE_EXISTING);
			} else {
				this.cryptor = cryptorProvider.createNew();
				byte[] keyFileContents = cryptor.writeKeysToMasterkeyFile(passphrase, Constants.VAULT_VERSION).serialize();
				Files.write(masterKeyPath, keyFileContents);
			}
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}

		this.dirIdProvider = new DirectoryIdProvider();
		this.cryptoPathMapper = new CryptoPathMapper(cryptor, dataRoot, getDirIdProvider());
		this.fileAttributeProvider = new CryptoFileAttributeProvider(cryptor.fileHeaderCryptor());
		this.openCryptoFiles = new OpenCryptoFiles(readonly);
	}

	static CryptoFileSystem cast(FileSystem fileSystem) {
		if (fileSystem instanceof CryptoFileSystem) {
			return (CryptoFileSystem) fileSystem;
		} else {
			throw new ProviderMismatchException();
		}
	}

	@Override
	public FileSystemProvider provider() {
		return provider;
	}

	@Override
	public void close() {
		cryptor.destroy();
		provider.getFileSystems().remove(pathToVault);
	}

	@Override
	public boolean isOpen() {
		return provider.getFileSystems().containsValue(this);
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

	CryptoPathMapper getCryptoPathMapper() {
		return cryptoPathMapper;
	}

	DirectoryIdProvider getDirIdProvider() {
		return dirIdProvider;
	}

	Cryptor getCryptor() {
		return cryptor;
	}

	CryptoFileAttributeProvider getFileAttributeProvider() {
		return fileAttributeProvider;
	}

	public OpenCryptoFiles getOpenCryptoFiles() {
		return openCryptoFiles;
	}

}
