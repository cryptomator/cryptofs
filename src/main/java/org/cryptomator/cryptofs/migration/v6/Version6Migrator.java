/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration.v6;

import org.cryptomator.cryptofs.common.BackupHelper;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener;
import org.cryptomator.cryptofs.migration.api.MigrationProgressListener;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.text.Normalizer.Form;

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
		MasterkeyFileAccess masterkeyFileAccess = new MasterkeyFileAccess(new byte[0], csprng);
		try (Masterkey masterkey = masterkeyFileAccess.load(masterkeyFile, passphrase)) {
			// create backup, as soon as we know the password was correct:
			Path masterkeyBackupFile = BackupHelper.attemptBackup(masterkeyFile);
			LOG.info("Backed up masterkey from {} to {}.", masterkeyFile.getFileName(), masterkeyBackupFile.getFileName());

			progressListener.update(MigrationProgressListener.ProgressState.FINALIZING, 0.0);

			// rewrite masterkey file with normalized passphrase:
			masterkeyFileAccess.persist(masterkey, masterkeyFile, Normalizer.normalize(passphrase, Form.NFC), 6);
			LOG.info("Updated masterkey.");
		}
		LOG.info("Upgraded {} from version 5 to version 6.", vaultRoot);
	}

}
