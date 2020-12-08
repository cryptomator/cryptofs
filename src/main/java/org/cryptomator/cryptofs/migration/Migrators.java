/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener;
import org.cryptomator.cryptofs.migration.api.MigrationProgressListener;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptofs.migration.api.NoApplicableMigratorException;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.common.MasterkeyFile;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Optional;

/**
 * Used to perform migration from an older vault format to a newer one.
 * <p>
 * Example Usage:
 *
 * <pre>
 * <code>
 * if (Migrators.get().{@link #needsMigration(Path, String, String)} needsMigration(pathToVault, vaultConfigFilename, masterkeyFileName)}) {
 * 	Migrators.get().{@link #migrate(Path, String, String, CharSequence, MigrationProgressListener, MigrationContinuationListener) migrate(pathToVault, masterkeyFileName, passphrase, progressListener, continuationListener)};
 * }
 * </code>
 * </pre>
 *
 * @since 1.4.0
 */
public class Migrators {

	private static final MigrationComponent COMPONENT = DaggerMigrationComponent.builder().csprng(strongSecureRandom()).build();

	private final Map<Migration, Migrator> migrators;
	private final FileSystemCapabilityChecker fsCapabilityChecker;

	@Inject
	Migrators(Map<Migration, Migrator> migrators, FileSystemCapabilityChecker fsCapabilityChecker) {
		this.migrators = migrators;
		this.fsCapabilityChecker = fsCapabilityChecker;
	}

	private static SecureRandom strongSecureRandom() {
		try {
			return SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("A strong algorithm must exist in every Java platform.", e);
		}
	}

	public static Migrators get() {
		return COMPONENT.migrators();
	}

	/**
	 * Inspects the vault and checks if it is supported by this library.
	 *
	 * @param pathToVault         Path to the vault's root
	 * @param vaultConfigFilename Name of the vault config file located in the vault
	 * @param masterkeyFilename   Name of the masterkey file optionally located in the vault
	 * @return <code>true</code> if the vault at the given path is of an older format than supported by this library
	 * @throws IOException if an I/O error occurs parsing the masterkey file
	 */
	public boolean needsMigration(Path pathToVault, String vaultConfigFilename, String masterkeyFilename) throws IOException {
		int vaultVersion = determineVaultVersion(pathToVault, vaultConfigFilename, masterkeyFilename);
		return vaultVersion < Constants.VAULT_VERSION;
	}

	/**
	 * Performs the actual migration. This task may take a while and this method will block.
	 *
	 * @param pathToVault          Path to the vault's root
	 * @param vaultConfigFilename  Name of the vault config file located inside <code>pathToVault</code>
	 * @param masterkeyFilename    Name of the masterkey file located inside <code>pathToVault</code>
	 * @param passphrase           The passphrase needed to unlock the vault
	 * @param progressListener     Listener that will get notified of progress updates
	 * @param continuationListener Listener that will get asked if there are events that require feedback
	 * @throws NoApplicableMigratorException                          If the vault can not be migrated, because no migrator could be found
	 * @throws InvalidPassphraseException                             If the passphrase could not be used to unlock the vault
	 * @throws FileSystemCapabilityChecker.MissingCapabilityException If the underlying filesystem lacks features required to store a vault
	 * @throws IOException                                            if an I/O error occurs migrating the vault
	 */
	public void migrate(Path pathToVault, String vaultConfigFilename, String masterkeyFilename, CharSequence passphrase, MigrationProgressListener progressListener, MigrationContinuationListener continuationListener) throws NoApplicableMigratorException, CryptoException, IOException {
		fsCapabilityChecker.assertAllCapabilities(pathToVault);
		int vaultVersion = determineVaultVersion(pathToVault, vaultConfigFilename, masterkeyFilename);
		try {
			Migrator migrator = findApplicableMigrator(vaultVersion).orElseThrow(NoApplicableMigratorException::new);
			migrator.migrate(pathToVault, vaultConfigFilename, masterkeyFilename, passphrase, progressListener, continuationListener);
		} catch (UnsupportedVaultFormatException e) {
			// might be a tampered masterkey file, as this exception is also thrown if the vault version MAC is not authentic.
			throw new IllegalStateException("Vault version checked beforehand but not supported by migrator.");
		}
	}

	private int determineVaultVersion(Path pathToVault, String vaultConfigFilename, String masterkeyFilename) throws IOException {
		Path vaultConfigPath = pathToVault.resolve(vaultConfigFilename);
		Path masterKeyPath = pathToVault.resolve(masterkeyFilename);
		if (Files.exists(vaultConfigPath)) {
			var jwt = Files.readString(vaultConfigPath);
			return VaultConfig.decode(jwt).allegedVaultVersion();
		} else if (Files.exists(masterKeyPath)) {
			return MasterkeyFile.withContentFromFile(masterKeyPath).allegedVaultVersion();
		} else {
			throw new IOException("Did not find " + vaultConfigFilename + " nor " + masterkeyFilename);
		}
	}

	private Optional<Migrator> findApplicableMigrator(int version) {
		return migrators.entrySet().stream().filter(entry -> entry.getKey().isApplicable(version)).map(Map.Entry::getValue).findAny();
	}

}
