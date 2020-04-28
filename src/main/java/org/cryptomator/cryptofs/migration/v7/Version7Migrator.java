/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration.v7;

import org.cryptomator.cryptofs.FileNameTooLongException;
import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;
import org.cryptomator.cryptofs.common.MasterkeyBackupFileHasher;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.DeletingFileVisitor;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener.ContinuationEvent;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener.ContinuationResult;
import org.cryptomator.cryptofs.migration.api.MigrationProgressListener;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.EnumSet;

public class Version7Migrator implements Migrator {

	private static final Logger LOG = LoggerFactory.getLogger(Version7Migrator.class);

	private final CryptorProvider cryptorProvider;

	@Inject
	public Version7Migrator(CryptorProvider cryptorProvider) {
		this.cryptorProvider = cryptorProvider;
	}

	@Override
	public void migrate(Path vaultRoot, String masterkeyFilename, CharSequence passphrase, MigrationProgressListener progressListener, MigrationContinuationListener continuationListener) throws InvalidPassphraseException, UnsupportedVaultFormatException, IOException {
		LOG.info("Upgrading {} from version 6 to version 7.", vaultRoot);
		progressListener.update(MigrationProgressListener.ProgressState.INITIALIZING, 0.0);
		Path masterkeyFile = vaultRoot.resolve(masterkeyFilename);
		byte[] fileContentsBeforeUpgrade = Files.readAllBytes(masterkeyFile);
		KeyFile keyFile = KeyFile.parse(fileContentsBeforeUpgrade);
		try (Cryptor cryptor = cryptorProvider.createFromKeyFile(keyFile, passphrase, 6)) {
			// create backup, as soon as we know the password was correct:
			Path masterkeyBackupFile = vaultRoot.resolve(masterkeyFilename + MasterkeyBackupFileHasher.generateFileIdSuffix(fileContentsBeforeUpgrade) + Constants.MASTERKEY_BACKUP_SUFFIX);
			Files.copy(masterkeyFile, masterkeyBackupFile, StandardCopyOption.REPLACE_EXISTING);
			LOG.info("Backed up masterkey from {} to {}.", masterkeyFile.getFileName(), masterkeyBackupFile.getFileName());
			
			// check file system capabilities:
			int pathLengthLimit = new FileSystemCapabilityChecker().determineSupportedPathLength(vaultRoot);
			VaultStatsVisitor vaultStats;
			if (pathLengthLimit >= Constants.MAX_CIPHERTEXT_PATH_LENGTH) {
				LOG.info("Underlying file system meets path length requirements.");
				vaultStats = new VaultStatsVisitor(vaultRoot, false);
			} else {
				LOG.warn("Underlying file system only supports paths with up to {} chars (required: {}). Asking for user feedback...", pathLengthLimit, Constants.MAX_CIPHERTEXT_PATH_LENGTH);
				ContinuationResult result = continuationListener.continueMigrationOnEvent(ContinuationEvent.REQUIRES_FULL_VAULT_DIR_SCAN);
				switch (result) {
					case PROCEED:
						vaultStats = new VaultStatsVisitor(vaultRoot, true);
						break;
					case CANCEL:
						LOG.info("Migration canceled by user.");
						return;
					default:
						throw new IllegalStateException("Unexpected result " + result);
				}
			}

			// dry-run to collect stats:
			Path dataDir = vaultRoot.resolve("d");
			Files.walkFileTree(dataDir, EnumSet.noneOf(FileVisitOption.class), 3, vaultStats);
			
			// fail if file names are too long:
			if (vaultStats.getMaxCiphertextPathLength() > pathLengthLimit) {
				LOG.error("Migration aborted due to lacking capabilities of underlying file system. Vault is unchanged.");
				throw new FileNameTooLongException(vaultStats.getLongestNewFile().toString(), pathLengthLimit);
			}
			
			// start migration:
			long toBeMigrated = vaultStats.getTotalFileCount();
			LOG.info("Starting migration of {} files", toBeMigrated);
			if (toBeMigrated > 0) {
				migrateFileNames(vaultRoot, progressListener, toBeMigrated);
			}

			// cleanup:
			progressListener.update(MigrationProgressListener.ProgressState.FINALIZING, 0.0);
			Files.walkFileTree(vaultRoot.resolve("m"), DeletingFileVisitor.INSTANCE);

			// rewrite masterkey file with normalized passphrase:
			byte[] fileContentsAfterUpgrade = cryptor.writeKeysToMasterkeyFile(passphrase, 7).serialize();
			Files.write(masterkeyFile, fileContentsAfterUpgrade, StandardOpenOption.TRUNCATE_EXISTING);
			LOG.info("Updated masterkey.");
		}
		LOG.info("Upgraded {} from version 6 to version 7.", vaultRoot);
	}

	private void migrateFileNames(Path vaultRoot, MigrationProgressListener progressListener, long totalFiles) throws IOException {
		assert totalFiles > 0;
		Path dataDir = vaultRoot.resolve("d");
		Files.walkFileTree(dataDir, EnumSet.noneOf(FileVisitOption.class), 3, new MigratingVisitor(vaultRoot, progressListener, totalFiles));
	}

}
