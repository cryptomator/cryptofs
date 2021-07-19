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
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.Collections;
import java.util.Map;

public class MigratorsTest {

	private Path pathToVault;
	private Path vaultConfigPath;
	private Path masterkeyPath;
	private FileSystemCapabilityChecker fsCapabilityChecker;

	@BeforeEach
	public void setup(@TempDir Path tmpDir) {
		pathToVault = tmpDir;
		vaultConfigPath = tmpDir.resolve("vault.cryptomator");
		masterkeyPath = tmpDir.resolve("masterkey.cryptomator");
		fsCapabilityChecker = Mockito.mock(FileSystemCapabilityChecker.class);
	}

	@Test
	@DisplayName("can't determine vault version without masterkey.cryptomator or vault.cryptomator")
	public void throwsExceptionIfNeitherMasterkeyNorVaultConfigExists() {
		Migrators migrators = new Migrators(Collections.emptyMap(), fsCapabilityChecker);

		IOException thrown = Assertions.assertThrows(IOException.class, () -> {
			migrators.needsMigration(pathToVault, "vault.cryptomator", "masterkey.cryptomator");
		});
		MatcherAssert.assertThat(thrown.getMessage(), CoreMatchers.containsString("Did not find vault.cryptomator nor masterkey.cryptomator"));
	}

	@Nested
	public class WithExistingVaultConfig {

		private MockedStatic<VaultConfig> vaultConfigClass;
		private VaultConfig.UnverifiedVaultConfig unverifiedVaultConfig;

		@BeforeEach
		public void setup() throws IOException {
			vaultConfigClass = Mockito.mockStatic(VaultConfig.class);
			unverifiedVaultConfig = Mockito.mock(VaultConfig.UnverifiedVaultConfig.class);

			Files.write(vaultConfigPath, "vault-config".getBytes(StandardCharsets.UTF_8));
			Assumptions.assumeTrue(Files.exists(vaultConfigPath));
			Assumptions.assumeFalse(Files.exists(masterkeyPath));

			vaultConfigClass.when(() -> VaultConfig.decode("vault-config")).thenReturn(unverifiedVaultConfig);
		}

		@AfterEach
		public void tearDown() {
			vaultConfigClass.close();
		}

		@Test
		@DisplayName("needs migration if vault version < Constants.VAULT_VERSION")
		public void testNeedsMigration() throws IOException {
			Mockito.when(unverifiedVaultConfig.allegedVaultVersion()).thenReturn(Constants.VAULT_VERSION - 1);
			Migrators migrators = new Migrators(Collections.emptyMap(), fsCapabilityChecker);

			boolean result = migrators.needsMigration(pathToVault, "vault.cryptomator", "masterkey.cryptomator");

			Assertions.assertTrue(result);
		}

		@Test
		@DisplayName("needs no migration if vault version >= Constants.VAULT_VERSION")
		public void testNeedsNoMigration() throws IOException {
			Mockito.when(unverifiedVaultConfig.allegedVaultVersion()).thenReturn(Constants.VAULT_VERSION);
			Migrators migrators = new Migrators(Collections.emptyMap(), fsCapabilityChecker);

			boolean result = migrators.needsMigration(pathToVault, "vault.cryptomator", "masterkey.cryptomator");

			Assertions.assertFalse(result);
		}

		@Test
		@DisplayName("throws NoApplicableMigratorException if no migrator was found")
		public void testMigrateWithoutMigrators() {
			Mockito.when(unverifiedVaultConfig.allegedVaultVersion()).thenReturn(42);

			Migrators migrators = new Migrators(Collections.emptyMap(), fsCapabilityChecker);
			Assertions.assertThrows(NoApplicableMigratorException.class, () -> {
				migrators.migrate(pathToVault, "vault.cryptomator", "masterkey.cryptomator", "secret", MigrationProgressListener.IGNORE, MigrationContinuationListener.CANCEL_ALWAYS);
			});
		}

		@Test
		@DisplayName("migrate successfully")
		@SuppressWarnings("deprecation")
		public void testMigrate() throws NoApplicableMigratorException, CryptoException, IOException {
			MigrationProgressListener progressListener = Mockito.mock(MigrationProgressListener.class);
			MigrationContinuationListener continuationListener = Mockito.mock(MigrationContinuationListener.class);
			Migrator migrator = Mockito.mock(Migrator.class);
			Mockito.when(unverifiedVaultConfig.allegedVaultVersion()).thenReturn(0);
			Migrators migrators = new Migrators(Map.of(Migration.ZERO_TO_ONE, migrator), fsCapabilityChecker);

			migrators.migrate(pathToVault, "vault.cryptomator", "masterkey.cryptomator", "secret", progressListener, continuationListener);

			Mockito.verify(migrator).migrate(pathToVault, "vault.cryptomator", "masterkey.cryptomator", "secret", progressListener, continuationListener);
		}

		@Test
		@DisplayName("migrate throws UnsupportedVaultFormatException")
		@SuppressWarnings("deprecation")
		public void testMigrateUnsupportedVaultFormat() throws NoApplicableMigratorException, CryptoException, IOException {
			Migrator migrator = Mockito.mock(Migrator.class);
			Migrators migrators = new Migrators(Map.of(Migration.ZERO_TO_ONE, migrator), fsCapabilityChecker);
			Mockito.when(unverifiedVaultConfig.allegedVaultVersion()).thenReturn(0);
			Mockito.doThrow(new UnsupportedVaultFormatException(Integer.MAX_VALUE, 1)).when(migrator).migrate(Mockito.any(), Mockito.anyString(), Mockito.anyString(), Mockito.any(), Mockito.any(), Mockito.any());

			Assertions.assertThrows(IllegalStateException.class, () -> {
				migrators.migrate(pathToVault, "vault.cryptomator", "masterkey.cryptomator", "secret", MigrationProgressListener.IGNORE, MigrationContinuationListener.CANCEL_ALWAYS);
			});
		}

	}

	@Nested
	public class WithExistingMasterkeyFile {

		private MockedStatic<MasterkeyFileAccess> masterkeyFileAccessClass;

		@BeforeEach
		public void setup() throws IOException {
			masterkeyFileAccessClass = Mockito.mockStatic(MasterkeyFileAccess.class);
			Files.createFile(masterkeyPath);
			Assumptions.assumeFalse(Files.exists(vaultConfigPath));
			Assumptions.assumeTrue(Files.exists(masterkeyPath));
		}

		@AfterEach
		public void tearDown() {
			masterkeyFileAccessClass.close();
		}

		@Test
		@DisplayName("needs migration if vault version < Constants.VAULT_VERSION")
		public void testNeedsMigration() throws IOException {
			masterkeyFileAccessClass.when(() -> MasterkeyFileAccess.readAllegedVaultVersion(Mockito.any())).thenReturn(Constants.VAULT_VERSION - 1);
			Migrators migrators = new Migrators(Collections.emptyMap(), fsCapabilityChecker);

			boolean result = migrators.needsMigration(pathToVault, "vault.cryptomator", "masterkey.cryptomator");

			Assertions.assertTrue(result);
		}

		@Test
		@DisplayName("needs no migration if vault version >= Constants.VAULT_VERSION")
		public void testNeedsNoMigration() throws IOException {
			masterkeyFileAccessClass.when(() -> MasterkeyFileAccess.readAllegedVaultVersion(Mockito.any())).thenReturn(Constants.VAULT_VERSION);
			Migrators migrators = new Migrators(Collections.emptyMap(), fsCapabilityChecker);

			boolean result = migrators.needsMigration(pathToVault, "vault.cryptomator", "masterkey.cryptomator");

			Assertions.assertFalse(result);
		}

		@Test
		@DisplayName("throws NoApplicableMigratorException if no migrator was found")
		public void testMigrateWithoutMigrators() {
			masterkeyFileAccessClass.when(() -> MasterkeyFileAccess.readAllegedVaultVersion(Mockito.any())).thenReturn(1337);

			Migrators migrators = new Migrators(Collections.emptyMap(), fsCapabilityChecker);
			Assertions.assertThrows(NoApplicableMigratorException.class, () -> {
				migrators.migrate(pathToVault, "vault.cryptomator", "masterkey.cryptomator", "secret", MigrationProgressListener.IGNORE, MigrationContinuationListener.CANCEL_ALWAYS);
			});
		}

		@Test
		@DisplayName("migrate successfully")
		@SuppressWarnings("deprecation")
		public void testMigrate() throws NoApplicableMigratorException, CryptoException, IOException {
			MigrationProgressListener progressListener = Mockito.mock(MigrationProgressListener.class);
			MigrationContinuationListener continuationListener = Mockito.mock(MigrationContinuationListener.class);
			Migrator migrator = Mockito.mock(Migrator.class);
			masterkeyFileAccessClass.when(() -> MasterkeyFileAccess.readAllegedVaultVersion(Mockito.any())).thenReturn(0);
			Migrators migrators = new Migrators(Map.of(Migration.ZERO_TO_ONE, migrator), fsCapabilityChecker);

			migrators.migrate(pathToVault, "vault.cryptomator", "masterkey.cryptomator", "secret", progressListener, continuationListener);

			Mockito.verify(migrator).migrate(pathToVault, "vault.cryptomator", "masterkey.cryptomator", "secret", progressListener, continuationListener);
		}

		@Test
		@DisplayName("migrate throws UnsupportedVaultFormatException")
		@SuppressWarnings("deprecation")
		public void testMigrateUnsupportedVaultFormat() throws NoApplicableMigratorException, CryptoException, IOException {
			Migrator migrator = Mockito.mock(Migrator.class);
			Migrators migrators = new Migrators(Map.of(Migration.ZERO_TO_ONE, migrator), fsCapabilityChecker);
			masterkeyFileAccessClass.when(() -> MasterkeyFileAccess.readAllegedVaultVersion(Mockito.any())).thenReturn(0);
			Mockito.doThrow(new UnsupportedVaultFormatException(Integer.MAX_VALUE, 1)).when(migrator).migrate(Mockito.any(), Mockito.anyString(), Mockito.anyString(), Mockito.any(), Mockito.any(), Mockito.any());

			Assertions.assertThrows(IllegalStateException.class, () -> {
				migrators.migrate(pathToVault, "vault.cryptomator", "masterkey.cryptomator", "secret", MigrationProgressListener.IGNORE, MigrationContinuationListener.CANCEL_ALWAYS);
			});
		}

	}

}
