/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Optional;

import javax.inject.Inject;

import org.cryptomator.cryptofs.Constants;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptofs.migration.api.NoApplicableMigratorException;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;

/**
 * Used to perform migration from an older vault format to a newer one.
 * <p>
 * Example Usage:
 * 
 * <pre>
 * <code>
 * if (Migrators.get().{@link #needsMigration(Path, String) needsMigration(pathToVault, masterkeyFileName)}) {
 * 	Migrators.get().{@link #migrate(Path, String, CharSequence) migrate(pathToVault, masterkeyFileName, passphrase)};
 * }
 * </code>
 * </pre>
 * 
 * @since 1.4.0
 */
public class Migrators {

	private static final MigrationComponent COMPONENT = DaggerMigrationComponent.builder() //
			.migrationModule(new MigrationModule(Cryptors.version1(strongSecureRandom()))) //
			.build();

	private final Map<Migration, Migrator> migrators;

	@Inject
	Migrators(Map<Migration, Migrator> migrators) {
		this.migrators = migrators;
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
	 * @param pathToVault Path to the vault's root
	 * @param masterkeyFilename Name of the masterkey file located in the vault
	 * @return <code>true</code> if the vault at the given path is of an older format than supported by this library
	 * @throws IOException if an I/O error occurs parsing the masterkey file
	 */
	public boolean needsMigration(Path pathToVault, String masterkeyFilename) throws IOException {
		Path masterKeyPath = pathToVault.resolve(masterkeyFilename);
		byte[] keyFileContents = Files.readAllBytes(masterKeyPath);
		KeyFile keyFile = KeyFile.parse(keyFileContents);
		return keyFile.getVersion() < Constants.VAULT_VERSION;
	}

	/**
	 * Performs the actual migration. This task may take a while and this method will block.
	 * 
	 * @param pathToVault Path to the vault's root
	 * @param masterkeyFilename Name of the masterkey file located in the vault
	 * @param passphrase The passphrase needed to unlock the vault
	 * @throws NoApplicableMigratorException If the vault can not be migrated, because no migrator could be found
	 * @throws InvalidPassphraseException If the passphrase could not be used to unlock the vault
	 * @throws IOException if an I/O error occurs migrating the vault
	 */
	public void migrate(Path pathToVault, String masterkeyFilename, CharSequence passphrase) throws NoApplicableMigratorException, InvalidPassphraseException, IOException {
		Path masterKeyPath = pathToVault.resolve(masterkeyFilename);
		byte[] keyFileContents = Files.readAllBytes(masterKeyPath);
		KeyFile keyFile = KeyFile.parse(keyFileContents);

		try {
			Migrator migrator = findApplicableMigrator(keyFile.getVersion()).orElseThrow(NoApplicableMigratorException::new);
			migrator.migrate(pathToVault, masterkeyFilename, passphrase);
		} catch (UnsupportedVaultFormatException e) {
			// might be a tampered masterkey file, as this exception is also thrown if the vault version MAC is not authentic.
			throw new IllegalStateException("Vault version checked beforehand but not supported by migrator.");
		}
	}

	private Optional<Migrator> findApplicableMigrator(int version) {
		// TODO return "5->6->7" instead of "5->6" and "6->7", if possible
		return migrators.entrySet().stream().filter(entry -> entry.getKey().isApplicable(version)).map(Map.Entry::getValue).findAny();
	}

}
