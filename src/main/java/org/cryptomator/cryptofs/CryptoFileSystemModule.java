/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs;

import dagger.Module;
import dagger.Provides;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.cryptomator.cryptofs.UncheckedThrows.rethrowUnchecked;

@Module
class CryptoFileSystemModule {

	@Provides
	@PerFileSystem
	public Cryptor provideCryptor(CryptorProvider cryptorProvider, @PathToVault Path pathToVault, CryptoFileSystemProperties properties, ReadonlyFlag readonlyFlag) {
		return rethrowUnchecked(IOException.class).from(() -> {
			Path masterKeyPath = pathToVault.resolve(properties.masterkeyFilename());
			Path backupKeyPath = pathToVault.resolve(properties.masterkeyFilename() + Constants.MASTERKEY_BACKUP_SUFFIX);
			assert Files.exists(masterKeyPath); // since 1.3.0 a file system can only be created for existing vaults. initialization is done before.
			byte[] keyFileContents = Files.readAllBytes(masterKeyPath);
			Cryptor cryptor = cryptorProvider.createFromKeyFile(KeyFile.parse(keyFileContents), properties.passphrase(), properties.pepper(), Constants.VAULT_VERSION);
			backupMasterkeyFileIfRequired(masterKeyPath, backupKeyPath, readonlyFlag);
			return cryptor;
		});
	}

	private void backupMasterkeyFileIfRequired(Path masterKeyPath, Path backupKeyPath, ReadonlyFlag readonlyFlag) throws IOException {
		if (!readonlyFlag.isSet()) {
			Files.copy(masterKeyPath, backupKeyPath, REPLACE_EXISTING);
		}
	}

}
