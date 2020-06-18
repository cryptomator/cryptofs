/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs;

import dagger.Module;
import dagger.Provides;
import org.cryptomator.cryptofs.attr.AttributeComponent;
import org.cryptomator.cryptofs.attr.AttributeViewComponent;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.MasterkeyBackupHelper;
import org.cryptomator.cryptofs.dir.DirectoryStreamComponent;
import org.cryptomator.cryptofs.fh.OpenCryptoFileComponent;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

@Module(subcomponents = {AttributeComponent.class, AttributeViewComponent.class, OpenCryptoFileComponent.class, DirectoryStreamComponent.class})
class CryptoFileSystemModule {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoFileSystemModule.class);

	@Provides
	@CryptoFileSystemScoped
	public Cryptor provideCryptor(CryptorProvider cryptorProvider, @PathToVault Path pathToVault, CryptoFileSystemProperties properties, ReadonlyFlag readonlyFlag) {
		try {
			Path masterKeyPath = pathToVault.resolve(properties.masterkeyFilename());
			assert Files.exists(masterKeyPath); // since 1.3.0 a file system can only be created for existing vaults. initialization is done before.
			byte[] keyFileContents = Files.readAllBytes(masterKeyPath);
			Cryptor cryptor = cryptorProvider.createFromKeyFile(KeyFile.parse(keyFileContents), properties.passphrase(), properties.pepper(), Constants.VAULT_VERSION);
			if (!readonlyFlag.isSet()) {
				MasterkeyBackupHelper.backupMasterKey(masterKeyPath);
			}
			return cryptor;
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	@Provides
	@CryptoFileSystemScoped
	public Optional<FileStore> provideNativeFileStore(@PathToVault Path pathToVault) {
		try {
			return Optional.of(Files.getFileStore(pathToVault));
		} catch (IOException e) {
			LOG.warn("Failed to get file store for " + pathToVault, e);
			return Optional.empty();
		}
	}
}
