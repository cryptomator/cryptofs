/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration.v6;

import org.cryptomator.cryptofs.common.MasterkeyBackupHelper;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener;
import org.cryptomator.cryptofs.migration.api.MigrationProgressListener;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.Optional;

/**
 * Updates masterkey.cryptomator:
 *
 * Version 6 encodes the passphrase in Unicode NFC.
 */
public class Version6Migrator implements Migrator {

	private static final Logger LOG = LoggerFactory.getLogger(Version6Migrator.class);

	private final SecureRandom csprng;

	@Inject
	public Version6Migrator(SecureRandom csprng) {
		this.csprng = csprng;
	}

	@Override
	public void migrate(Path vaultRoot, String vaultConfigFilename, String masterkeyFilename, CharSequence passphrase, MigrationProgressListener progressListener, MigrationContinuationListener continuationListener) throws CryptoException, IOException {
		LOG.info("Upgrading {} from version 5 to version 6.", vaultRoot);
		progressListener.update(MigrationProgressListener.ProgressState.INITIALIZING, 0.0);
		Path masterkeyFile = vaultRoot.resolve(masterkeyFilename);
		byte[] fileContentsBeforeUpgrade = Files.readAllBytes(masterkeyFile);
		MasterkeyFile keyFile = MasterkeyFile.withContentFromFile(masterkeyFile);
		try (Masterkey masterkey = keyFile.unlock(passphrase, new byte[0], Optional.of(5)).loadKeyAndClose()) {
			// create backup, as soon as we know the password was correct:
			Path masterkeyBackupFile = MasterkeyBackupHelper.attemptMasterKeyBackup(masterkeyFile);
			LOG.info("Backed up masterkey from {} to {}.", masterkeyFile.getFileName(), masterkeyBackupFile.getFileName());

			progressListener.update(MigrationProgressListener.ProgressState.FINALIZING, 0.0);
			
			// rewrite masterkey file with normalized passphrase:
			byte[] fileContentsAfterUpgrade = MasterkeyFile.lock(masterkey, Normalizer.normalize(passphrase, Form.NFC), new byte[0], 6, csprng);
			Files.write(masterkeyFile, fileContentsAfterUpgrade, StandardOpenOption.TRUNCATE_EXISTING);
			LOG.info("Updated masterkey.");
		}
		LOG.info("Upgraded {} from version 5 to version 6.", vaultRoot);
	}

}
