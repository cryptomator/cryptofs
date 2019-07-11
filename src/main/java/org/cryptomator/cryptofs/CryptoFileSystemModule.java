/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.io.BaseEncoding;
import dagger.Module;
import dagger.Provides;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

@Module
class CryptoFileSystemModule {

	@Provides
	@CryptoFileSystemScoped
	public Cryptor provideCryptor(CryptorProvider cryptorProvider, @PathToVault Path pathToVault, CryptoFileSystemProperties properties, ReadonlyFlag readonlyFlag) {
		try {
			Path masterKeyPath = pathToVault.resolve(properties.masterkeyFilename());
			assert Files.exists(masterKeyPath); // since 1.3.0 a file system can only be created for existing vaults. initialization is done before.
			byte[] keyFileContents = Files.readAllBytes(masterKeyPath);
			Path backupKeyPath = pathToVault.resolve(properties.masterkeyFilename() + generateFileId(keyFileContents) + Constants.MASTERKEY_BACKUP_SUFFIX);
			Cryptor cryptor = cryptorProvider.createFromKeyFile(KeyFile.parse(keyFileContents), properties.passphrase(), properties.pepper(), Constants.VAULT_VERSION);
			backupMasterkeyFileIfRequired(masterKeyPath, backupKeyPath, readonlyFlag);
			return cryptor;
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private String generateFileId(byte[] fileBytes) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(fileBytes);
			return BaseEncoding.base16().encode(digest, 0, 4);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Every Java Platform must support the Message Digest algorithm SHA-256");
		}
	}

	private void backupMasterkeyFileIfRequired(Path masterKeyPath, Path backupKeyPath, ReadonlyFlag readonlyFlag) throws IOException {
		if (!readonlyFlag.isSet()) {
			Files.copy(masterKeyPath, backupKeyPath, REPLACE_EXISTING);
		}
	}

}
