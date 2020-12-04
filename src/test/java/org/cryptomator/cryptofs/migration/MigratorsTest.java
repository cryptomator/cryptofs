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
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener.ContinuationResult;
import org.cryptomator.cryptofs.migration.api.MigrationProgressListener;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptofs.migration.api.NoApplicableMigratorException;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.common.MasterkeyFile;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;

public class MigratorsTest {

	private MockedStatic<Files> filesClass;
	private Path pathToVault;
	private FileSystemCapabilityChecker fsCapabilityChecker;
	private Path vaultConfigPath;
	private Path masterkeyPath;

	@BeforeEach
	public void setup() {
		filesClass = Mockito.mockStatic(Files.class);
		pathToVault = Mockito.mock(Path.class, "path/to/vault");
		fsCapabilityChecker = Mockito.mock(FileSystemCapabilityChecker.class);
		vaultConfigPath = Mockito.mock(Path.class, "path/to/vault/vault.cryptomator");
		masterkeyPath = Mockito.mock(Path.class, "path/to/vault/masterkey.cryptomator");

		Mockito.when(pathToVault.resolve("masterkey.cryptomator")).thenReturn(masterkeyPath);
		Mockito.when(pathToVault.resolve("vault.cryptomator")).thenReturn(vaultConfigPath);
	}

	@AfterEach
	public void tearDown() {
		filesClass.close();
	}

	@Test
	@DisplayName("can't determine vault version without masterkey.cryptomator or vault.cryptomator")
	public void throwsExceptionIfNeitherMasterkeyNorVaultConfigExists() {
		filesClass.when(() -> Files.exists(vaultConfigPath)).thenReturn(false);
		filesClass.when(() -> Files.exists(masterkeyPath)).thenReturn(false);

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
		public void setup() {
			Assumptions.assumeFalse(Files.exists(masterkeyPath));
			vaultConfigClass = Mockito.mockStatic(VaultConfig.class);
			unverifiedVaultConfig = Mockito.mock(VaultConfig.UnverifiedVaultConfig.class);

			filesClass.when(() -> Files.exists(vaultConfigPath)).thenReturn(true);
			filesClass.when(() -> Files.readString(vaultConfigPath)).thenReturn("vault-config");
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

		private MockedStatic<MasterkeyFile> masterkeyFileClass;
		private MasterkeyFile masterkeyFile;

		@BeforeEach
		public void setup() {
			Assumptions.assumeFalse(Files.exists(vaultConfigPath));
			masterkeyFileClass = Mockito.mockStatic(MasterkeyFile.class);
			masterkeyFile = Mockito.mock(MasterkeyFile.class);

			filesClass.when(() -> Files.exists(masterkeyPath)).thenReturn(true);
			masterkeyFileClass.when(() -> MasterkeyFile.withContentFromFile(masterkeyPath)).thenReturn(masterkeyFile);
		}

		@AfterEach
		public void tearDown() {
			masterkeyFileClass.close();
		}

		@Test
		@DisplayName("needs migration if vault version < Constants.VAULT_VERSION")
		public void testNeedsMigration() throws IOException {
			Mockito.when(masterkeyFile.allegedVaultVersion()).thenReturn(Constants.VAULT_VERSION - 1);
			Migrators migrators = new Migrators(Collections.emptyMap(), fsCapabilityChecker);

			boolean result = migrators.needsMigration(pathToVault, "vault.cryptomator", "masterkey.cryptomator");

			Assertions.assertTrue(result);
		}

		@Test
		@DisplayName("needs no migration if vault version >= Constants.VAULT_VERSION")
		public void testNeedsNoMigration() throws IOException {
			Mockito.when(masterkeyFile.allegedVaultVersion()).thenReturn(Constants.VAULT_VERSION);
			Migrators migrators = new Migrators(Collections.emptyMap(), fsCapabilityChecker);

			boolean result = migrators.needsMigration(pathToVault, "vault.cryptomator", "masterkey.cryptomator");

			Assertions.assertFalse(result);
		}

		@Test
		@DisplayName("throws NoApplicableMigratorException if no migrator was found")
		public void testMigrateWithoutMigrators() {
			Mockito.when(masterkeyFile.allegedVaultVersion()).thenReturn(42);

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
			Mockito.when(masterkeyFile.allegedVaultVersion()).thenReturn(0);
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
			Mockito.when(masterkeyFile.allegedVaultVersion()).thenReturn(0);
			Mockito.doThrow(new UnsupportedVaultFormatException(Integer.MAX_VALUE, 1)).when(migrator).migrate(Mockito.any(), Mockito.anyString(), Mockito.anyString(), Mockito.any(), Mockito.any(), Mockito.any());

			Assertions.assertThrows(IllegalStateException.class, () -> {
				migrators.migrate(pathToVault, "vault.cryptomator", "masterkey.cryptomator", "secret", MigrationProgressListener.IGNORE, MigrationContinuationListener.CANCEL_ALWAYS);
			});
		}

	}

}
