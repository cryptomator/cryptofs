/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration.v6;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.text.Normalizer;
import java.text.Normalizer.Form;

import javax.inject.Inject;

import org.cryptomator.cryptofs.Constants;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Version6Migrator implements Migrator {

	private static final Logger LOG = LoggerFactory.getLogger(Version6Migrator.class);

	private final CryptorProvider cryptorProvider;

	@Inject
	public Version6Migrator(CryptorProvider cryptorProvider) {
		this.cryptorProvider = cryptorProvider;
	}

	@Override
	public void migrate(Path vaultRoot, String masterkeyFilename, CharSequence passphrase) throws InvalidPassphraseException, UnsupportedVaultFormatException, IOException {
		LOG.info("Upgrading {} from version 5 to version 6.", vaultRoot);
		Path masterkeyFile = vaultRoot.resolve(masterkeyFilename);
		byte[] fileContentsBeforeUpgrade = Files.readAllBytes(masterkeyFile);
		KeyFile keyFile = KeyFile.parse(fileContentsBeforeUpgrade);
		try (Cryptor cryptor = cryptorProvider.createFromKeyFile(keyFile, passphrase, 5)) {
			// create backup, as soon as we know the password was correct:
			Path masterkeyBackupFile = vaultRoot.resolve(masterkeyFilename + Constants.MASTERKEY_BACKUP_SUFFIX);
			Files.copy(masterkeyFile, masterkeyBackupFile, StandardCopyOption.REPLACE_EXISTING);
			LOG.info("Backed up masterkey from {} to {}.", masterkeyFile.getFileName(), masterkeyBackupFile.getFileName());
			// rewrite masterkey file with normalized passphrase:
			byte[] fileContentsAfterUpgrade = cryptor.writeKeysToMasterkeyFile(Normalizer.normalize(passphrase, Form.NFC), 6).serialize();
			Files.write(masterkeyFile, fileContentsAfterUpgrade, StandardOpenOption.TRUNCATE_EXISTING);
			LOG.info("Updated masterkey.");
		}
		LOG.info("Upgraded {} from version 5 to version 6.", vaultRoot);
	}

}
