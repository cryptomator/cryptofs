/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration.api;

import java.io.IOException;
import java.nio.file.Path;

import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;

/**
 * @since 1.4.0
 */
public interface Migrator {

	/**
	 * Performs the migration this migrator is built for.
	 * 
	 * @param vaultRoot
	 * @param masterkeyFilename
	 * @param passphrase
	 * @throws InvalidPassphraseException
	 * @throws UnsupportedVaultFormatException
	 * @throws IOException
	 */
	void migrate(Path vaultRoot, String masterkeyFilename, CharSequence passphrase) throws InvalidPassphraseException, UnsupportedVaultFormatException, IOException;

	/**
	 * Chains this migrator with a consecutive migrator.
	 * 
	 * @param nextMigration The next migrator able to read the vault format created by this migrator.
	 * @return A combined migrator performing both steps in order.
	 */
	default Migrator andThen(Migrator nextMigration) {
		return (Path vaultRoot, String masterkeyFilename, CharSequence passphrase) -> {
			migrate(vaultRoot, masterkeyFilename, passphrase);
			nextMigration.migrate(vaultRoot, masterkeyFilename, passphrase);
		};
	}

}
