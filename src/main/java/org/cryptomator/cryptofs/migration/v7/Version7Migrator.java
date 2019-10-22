/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration.v7;

import org.cryptomator.cryptofs.BackupUtil;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.DeletingFileVisitor;
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
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.EnumSet;
import java.util.concurrent.atomic.LongAdder;

public class Version7Migrator implements Migrator {

	private static final Logger LOG = LoggerFactory.getLogger(Version7Migrator.class);

	private final CryptorProvider cryptorProvider;

	@Inject
	public Version7Migrator(CryptorProvider cryptorProvider) {
		this.cryptorProvider = cryptorProvider;
	}

	@Override
	public void migrate(Path vaultRoot, String masterkeyFilename, CharSequence passphrase, MigrationProgressListener progressListener) throws InvalidPassphraseException, UnsupportedVaultFormatException, IOException {
		LOG.info("Upgrading {} from version 6 to version 7.", vaultRoot);
		progressListener.update(MigrationProgressListener.ProgressState.INITIALIZING, 0.0);
		Path masterkeyFile = vaultRoot.resolve(masterkeyFilename);
		byte[] fileContentsBeforeUpgrade = Files.readAllBytes(masterkeyFile);
		KeyFile keyFile = KeyFile.parse(fileContentsBeforeUpgrade);
		try (Cryptor cryptor = cryptorProvider.createFromKeyFile(keyFile, passphrase, 6)) {
			// create backup, as soon as we know the password was correct:
			Path masterkeyBackupFile = vaultRoot.resolve(masterkeyFilename + BackupUtil.generateFileIdSuffix(fileContentsBeforeUpgrade) + Constants.MASTERKEY_BACKUP_SUFFIX);
			Files.copy(masterkeyFile, masterkeyBackupFile, StandardCopyOption.REPLACE_EXISTING);
			LOG.info("Backed up masterkey from {} to {}.", masterkeyFile.getFileName(), masterkeyBackupFile.getFileName());

			long toBeMigrated = countFileNames(vaultRoot);
			if (toBeMigrated > 0) {
				migrateFileNames(vaultRoot, progressListener, toBeMigrated);
			}

			progressListener.update(MigrationProgressListener.ProgressState.FINALIZING, 0.0);

			// remove deprecated /m/ directory
			Files.walkFileTree(vaultRoot.resolve("m"), DeletingFileVisitor.INSTANCE);

			// rewrite masterkey file with normalized passphrase:
			byte[] fileContentsAfterUpgrade = cryptor.writeKeysToMasterkeyFile(passphrase, 7).serialize();
			Files.write(masterkeyFile, fileContentsAfterUpgrade, StandardOpenOption.TRUNCATE_EXISTING);
			LOG.info("Updated masterkey.");
		}
		LOG.info("Upgraded {} from version 6 to version 7.", vaultRoot);
	}
	
	private long countFileNames(Path vaultRoot) throws IOException {
		LongAdder counter = new LongAdder();
		Path dataDir = vaultRoot.resolve("d");
		Files.walkFileTree(dataDir, EnumSet.noneOf(FileVisitOption.class), 3, new SimpleFileVisitor<Path>() {

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
				counter.increment();
				return FileVisitResult.CONTINUE;
			}
		});
		return counter.sum();
	}

	private void migrateFileNames(Path vaultRoot, MigrationProgressListener progressListener, long totalFiles) throws IOException {
		assert totalFiles > 0;
		Path dataDir = vaultRoot.resolve("d");
		Files.walkFileTree(dataDir, EnumSet.noneOf(FileVisitOption.class), 3, new MigratingVisitor(vaultRoot, progressListener, totalFiles));
	}

}
