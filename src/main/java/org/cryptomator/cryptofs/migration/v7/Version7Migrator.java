/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration.v7;

import org.cryptomator.cryptofs.FileNameTooLongException;
import org.cryptomator.cryptofs.common.DeletingFileVisitor;
import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;
import org.cryptomator.cryptofs.common.MasterkeyBackupHelper;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener.ContinuationEvent;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener.ContinuationResult;
import org.cryptomator.cryptofs.migration.api.MigrationProgressListener;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.Optional;

/**
 * Renames ciphertext names:
 *
 * <ul>
 *     <li>Files: BASE32== → base64==.c9r</li>
 *     <li>Dirs: 0BASE32== → base64==.c9r/dir.c9r</li>
 *     <li>Symlinks: 1SBASE32== → base64.c9r/symlink.c9r</li>
 * </ul>
 * <p>
 * Shortened names:
 * <ul>
 *     <li>shortened.lng → shortened.c9s</li>
 *     <li>m/shortened.lng → shortened.c9s/contents.c9r</li>
 * </ul>
 */
public class Version7Migrator implements Migrator {

	private static final Logger LOG = LoggerFactory.getLogger(Version7Migrator.class);

	private final SecureRandom csprng;

	@Inject
	public Version7Migrator(SecureRandom csprng) {
		this.csprng = csprng;
	}

	@Override
	public void migrate(Path vaultRoot, String vaultConfigFilename, String masterkeyFilename, CharSequence passphrase, MigrationProgressListener progressListener, MigrationContinuationListener continuationListener) throws CryptoException, IOException {
		LOG.info("Upgrading {} from version 6 to version 7.", vaultRoot);
		progressListener.update(MigrationProgressListener.ProgressState.INITIALIZING, 0.0);
		Path masterkeyFile = vaultRoot.resolve(masterkeyFilename);
		MasterkeyFile keyFile = MasterkeyFile.withContentFromFile(masterkeyFile);
		try (Masterkey masterkey = keyFile.unlock(passphrase, new byte[0], Optional.of(6)).loadKeyAndClose()) {
			// create backup, as soon as we know the password was correct:
			Path masterkeyBackupFile = MasterkeyBackupHelper.attemptMasterKeyBackup(masterkeyFile);
			LOG.info("Backed up masterkey from {} to {}.", masterkeyFile.getFileName(), masterkeyBackupFile.getFileName());

			// check file system capabilities:
			int filenameLengthLimit = new FileSystemCapabilityChecker().determineSupportedFileNameLength(vaultRoot.resolve("c"), 46, 28, 220);
			int pathLengthLimit = filenameLengthLimit + 48; // TODO
			PreMigrationVisitor preMigrationVisitor;
			if (filenameLengthLimit >= 220) {
				LOG.info("Underlying file system meets filename length requirements.");
				preMigrationVisitor = new PreMigrationVisitor(vaultRoot, false);
			} else {
				LOG.warn("Underlying file system only supports names with up to {} chars (required: 220). Asking for user feedback...", filenameLengthLimit);
				ContinuationResult result = continuationListener.continueMigrationOnEvent(ContinuationEvent.REQUIRES_FULL_VAULT_DIR_SCAN);
				switch (result) {
					case PROCEED:
						preMigrationVisitor = new PreMigrationVisitor(vaultRoot, true);
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
			Files.walkFileTree(dataDir, EnumSet.noneOf(FileVisitOption.class), 3, preMigrationVisitor);

			// fail if ciphertext paths are too long:
			if (preMigrationVisitor.getMaxCiphertextPathLength() > pathLengthLimit) {
				LOG.error("Migration aborted due to unsupported path length (required {}) of underlying file system (supports {}). Vault is unchanged.", preMigrationVisitor.getMaxCiphertextPathLength(), pathLengthLimit);
				throw new FileNameTooLongException(preMigrationVisitor.getLongestPath().toString(), pathLengthLimit, filenameLengthLimit);
			}

			// fail if ciphertext names are too long:
			if (preMigrationVisitor.getMaxCiphertextNameLength() > filenameLengthLimit) {
				LOG.error("Migration aborted due to unsupported filename length (required {}) of underlying file system (supports {}). Vault is unchanged.", preMigrationVisitor.getMaxCiphertextNameLength(), filenameLengthLimit);
				throw new FileNameTooLongException(preMigrationVisitor.getPathWithLongestName().toString(), pathLengthLimit, filenameLengthLimit);
			}

			// start migration:
			long toBeMigrated = preMigrationVisitor.getTotalFileCount();
			LOG.info("Starting migration of {} files", toBeMigrated);
			if (toBeMigrated > 0) {
				migrateFileNames(vaultRoot, progressListener, toBeMigrated);
			}

			// cleanup:
			progressListener.update(MigrationProgressListener.ProgressState.FINALIZING, 0.0);
			Files.walkFileTree(vaultRoot.resolve("m"), DeletingFileVisitor.INSTANCE);

			// rewrite masterkey file with normalized passphrase:
			byte[] fileContentsAfterUpgrade = MasterkeyFile.lock(masterkey, passphrase, new byte[0], 7, csprng);
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
