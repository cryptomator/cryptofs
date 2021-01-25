/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration.v8;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.cryptomator.cryptofs.common.MasterkeyBackupHelper;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

/**
 * Splits up <code>masterkey.cryptomator</code>:
 *
 * <ul>
 *     <li><code>vault.cryptomator</code> contains vault version and vault-specific metadata</li>
 *     <li><code>masterkey.cryptomator</code> contains KDF params and may become obsolete when other key sources are supported</li>
 * </ul>
 */
public class Version8Migrator implements Migrator {

	private static final Logger LOG = LoggerFactory.getLogger(Version8Migrator.class);

	private final SecureRandom csprng;

	@Inject
	public Version8Migrator(SecureRandom csprng) {
		this.csprng = csprng;
	}

	@Override
	public void migrate(Path vaultRoot, String vaultConfigFilename, String masterkeyFilename, CharSequence passphrase, MigrationProgressListener progressListener, MigrationContinuationListener continuationListener) throws CryptoException, IOException {
		LOG.info("Upgrading {} from version 7 to version 8.", vaultRoot);
		progressListener.update(MigrationProgressListener.ProgressState.INITIALIZING, 0.0);
		Path masterkeyFile = vaultRoot.resolve(masterkeyFilename);
		Path vaultConfigFile = vaultRoot.resolve(vaultConfigFilename);
		byte[] rawKey = new byte[0];
		MasterkeyFileAccess masterkeyFileAccess = new MasterkeyFileAccess(new byte[0], csprng);
		try (Masterkey masterkey = masterkeyFileAccess.load(masterkeyFile, passphrase)) {
			// create backup, as soon as we know the password was correct:
			Path masterkeyBackupFile = MasterkeyBackupHelper.attemptMasterKeyBackup(masterkeyFile);
			LOG.info("Backed up masterkey from {} to {}.", masterkeyFile.getFileName(), masterkeyBackupFile.getFileName());

			// create vaultconfig.cryptomator
			rawKey = masterkey.getEncoded();
			Algorithm algorithm = Algorithm.HMAC256(rawKey);
			var config = JWT.create() //
					.withJWTId(UUID.randomUUID().toString()) //
					.withKeyId("MASTERKEY_FILE") //
					.withClaim("format", 8) //
					.withClaim("cipherCombo", "SIV_CTRMAC") //
					.withClaim("maxFilenameLen", 220) //
					.sign(algorithm);
			Files.writeString(vaultConfigFile, config, StandardCharsets.US_ASCII, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
			LOG.info("Wrote vault config to {}.", vaultConfigFile);

			progressListener.update(MigrationProgressListener.ProgressState.FINALIZING, 0.0);

			// rewrite masterkey file with normalized passphrase:
			masterkeyFileAccess.persist(masterkey, masterkeyFile, passphrase, 999);
			LOG.info("Updated masterkey.");
		} finally {
			Arrays.fill(rawKey, (byte) 0x00);
		}
		LOG.info("Upgraded {} from version 7 to version 8.", vaultRoot);
	}

}
