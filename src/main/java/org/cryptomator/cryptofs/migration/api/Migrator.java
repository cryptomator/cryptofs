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
	default void migrate(Path vaultRoot, String masterkeyFilename, CharSequence passphrase) throws InvalidPassphraseException, UnsupportedVaultFormatException, IOException {
		migrate(vaultRoot, masterkeyFilename, passphrase, (state, progress) -> {});
	}

	/**
	 * Performs the migration this migrator is built for.
	 *
	 * @param vaultRoot
	 * @param masterkeyFilename
	 * @param passphrase
	 * @param progressListener 
	 * @throws InvalidPassphraseException
	 * @throws UnsupportedVaultFormatException
	 * @throws IOException
	 */
	default void migrate(Path vaultRoot, String masterkeyFilename, CharSequence passphrase, MigrationProgressListener progressListener) throws InvalidPassphraseException, UnsupportedVaultFormatException, IOException {
		migrate(vaultRoot, masterkeyFilename, passphrase, progressListener, (event) -> MigrationContinuationListener.ContinuationResult.CANCEL);
	}

	/**
	 * Performs the migration this migrator is built for.
	 *
	 * @param vaultRoot
	 * @param masterkeyFilename
	 * @param passphrase
	 * @param progressListener
	 * @param continuationListener
	 * @throws InvalidPassphraseException
	 * @throws UnsupportedVaultFormatException
	 * @throws IOException
	 */
	void migrate(Path vaultRoot, String masterkeyFilename, CharSequence passphrase, MigrationProgressListener progressListener, MigrationContinuationListener continuationListener) throws InvalidPassphraseException, UnsupportedVaultFormatException, IOException;

}
