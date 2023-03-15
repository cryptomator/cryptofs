package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.BackupHelper;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CryptoFileSystemsTest {

	private final Path pathToVault = mock(Path.class, "vaultPath");
	private final Path normalizedPathToVault = mock(Path.class, "normalizedVaultPath");
	private final Path configFilePath = mock(Path.class, "normalizedVaultPath/vault.cryptomator");
	private final Path configFileBackupPath = mock(Path.class, "normalizedVaultPath/vault.cryptomator.12345678.bkup");
	private final Path dataDirPath = mock(Path.class, "normalizedVaultPath/d");
	private final Path preContenRootPath = mock(Path.class, "normalizedVaultPath/d/AB");
	private final Path contenRootPath = mock(Path.class, "normalizedVaultPath/d/AB/CDEFGHIJKLMNOP");
	private final FileSystemCapabilityChecker capabilityChecker = mock(FileSystemCapabilityChecker.class);
	private final CryptoFileSystemProvider provider = mock(CryptoFileSystemProvider.class);
	private final CryptoFileSystemProperties properties = mock(CryptoFileSystemProperties.class);
	private final CryptoFileSystemComponent cryptoFileSystemComponent = mock(CryptoFileSystemComponent.class);
	private final CryptoFileSystemImpl cryptoFileSystem = mock(CryptoFileSystemImpl.class);
	private final VaultConfig.UnverifiedVaultConfig configLoader = mock(VaultConfig.UnverifiedVaultConfig.class);
	private final MasterkeyLoader keyLoader = mock(MasterkeyLoader.class);
	private final Masterkey masterkey = mock(Masterkey.class);
	private final Masterkey clonedMasterkey = Mockito.mock(Masterkey.class);
	private final byte[] rawKey = new byte[64];
	private final VaultConfig vaultConfig = mock(VaultConfig.class);
	private final CryptorProvider.Scheme cipherCombo = mock(CryptorProvider.Scheme.class);
	private final SecureRandom csprng = Mockito.mock(SecureRandom.class);
	private final CryptorProvider cryptorProvider = mock(CryptorProvider.class);
	private final Cryptor cryptor = mock(Cryptor.class);
	private final FileNameCryptor fileNameCryptor = mock(FileNameCryptor.class);
	private final CryptoFileSystemComponent.Factory cryptoFileSystemComponentFactory = mock(CryptoFileSystemComponent.Factory.class);


	private MockedStatic<VaultConfig> vaultConficClass;
	private MockedStatic<Files> filesClass;
	private MockedStatic<CryptorProvider> cryptorProviderClass;
	private MockedStatic<BackupHelper> backupHelperClass;

	private final CryptoFileSystems inTest = new CryptoFileSystems(cryptoFileSystemComponentFactory, capabilityChecker, csprng);

	@BeforeEach
	public void setup() throws IOException, MasterkeyLoadingFailedException {
		vaultConficClass = Mockito.mockStatic(VaultConfig.class);
		filesClass = Mockito.mockStatic(Files.class);
		cryptorProviderClass = Mockito.mockStatic(CryptorProvider.class);
		backupHelperClass = Mockito.mockStatic(BackupHelper.class);

		when(pathToVault.normalize()).thenReturn(normalizedPathToVault);
		when(normalizedPathToVault.resolve("vault.cryptomator")).thenReturn(configFilePath);
		when(properties.vaultConfigFilename()).thenReturn("vault.cryptomator");
		when(properties.keyLoader()).thenReturn(keyLoader);
		filesClass.when(() -> Files.readString(configFilePath, StandardCharsets.US_ASCII)).thenReturn("jwt-vault-config");
		vaultConficClass.when(() -> VaultConfig.decode("jwt-vault-config")).thenReturn(configLoader);
		cryptorProviderClass.when(() -> CryptorProvider.forScheme(cipherCombo)).thenReturn(cryptorProvider);
		backupHelperClass.when(() -> BackupHelper.attemptBackup(configFilePath)).thenReturn(configFileBackupPath);
		when(VaultConfig.decode("jwt-vault-config")).thenReturn(configLoader);
		when(configLoader.getKeyId()).thenReturn(URI.create("test:key"));
		when(keyLoader.loadKey(Mockito.any())).thenReturn(masterkey);
		when(masterkey.getEncoded()).thenReturn(rawKey);
		when(masterkey.copy()).thenReturn(clonedMasterkey);
		when(configLoader.verify(rawKey, Constants.VAULT_VERSION)).thenReturn(vaultConfig);
		when(cryptorProvider.provide(clonedMasterkey, csprng)).thenReturn(cryptor);
		when(vaultConfig.getCipherCombo()).thenReturn(cipherCombo);
		when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		when(fileNameCryptor.hashDirectoryId("")).thenReturn("ABCDEFGHIJKLMNOP");
		when(pathToVault.resolve(Constants.DATA_DIR_NAME)).thenReturn(dataDirPath);
		when(dataDirPath.resolve("AB")).thenReturn(preContenRootPath);
		when(preContenRootPath.resolve("CDEFGHIJKLMNOP")).thenReturn(contenRootPath);
		filesClass.when(() -> Files.exists(contenRootPath)).thenReturn(true);
		when(cryptoFileSystemComponentFactory.create(any(),any(),any(),any(),any())).thenReturn(cryptoFileSystemComponent);
		when(cryptoFileSystemComponent.cryptoFileSystem()).thenReturn(cryptoFileSystem);
	}

	@AfterEach
	public void tearDown() {
		vaultConficClass.close();
		filesClass.close();
		cryptorProviderClass.close();
		backupHelperClass.close();
	}

	@Test
	public void testContainsReturnsFalseForNonContainedFileSystem() {
		Assertions.assertFalse(inTest.contains(cryptoFileSystem));
	}

	@Test
	public void testContainsReturnsTrueForContainedFileSystem() throws IOException, MasterkeyLoadingFailedException {
		CryptoFileSystemImpl impl = inTest.create(provider, pathToVault, properties);

		Assertions.assertSame(cryptoFileSystem, impl);
		Assertions.assertTrue(inTest.contains(cryptoFileSystem));
		verify(cryptoFileSystemComponentFactory,Mockito.times(1)).create(cryptor, vaultConfig, provider, normalizedPathToVault, properties);
	}

	@Test
	public void testCreateThrowsFileSystemAlreadyExistsExceptionIfInvokedWithSamePathTwice() throws IOException, MasterkeyLoadingFailedException {
		inTest.create(provider, pathToVault, properties);

		Assertions.assertThrows(FileSystemAlreadyExistsException.class, () -> {
			inTest.create(provider, pathToVault, properties);
		});
	}

	@Test
	public void testCreateDoesNotThrowFileSystemAlreadyExistsExceptionIfFileSystemIsRemovedBefore() throws IOException, MasterkeyLoadingFailedException {
		CryptoFileSystemImpl fileSystem1 = inTest.create(provider, pathToVault, properties);
		Assertions.assertTrue(inTest.contains(fileSystem1));
		inTest.remove(fileSystem1);
		Assertions.assertFalse(inTest.contains(fileSystem1));

		CryptoFileSystemImpl fileSystem2 = inTest.create(provider, pathToVault, properties);
		Assertions.assertTrue(inTest.contains(fileSystem2));
	}

	@Test
	public void testCreateThrowsIOExceptionIfContentRootExistenceCheckFails() {
		filesClass.when(() -> Files.exists(contenRootPath)).thenReturn(false);

		Assertions.assertThrows(IOException.class, () -> inTest.create(provider, pathToVault, properties));
	}

	@Test
	public void testCreateAttemptsBackupOnSuccessfulVerification() throws IOException {
		inTest.create(provider, pathToVault, properties);
		backupHelperClass.verify(() -> BackupHelper.attemptBackup(configFilePath));
	}

	@Test
	public void testCreateWithFailedConfigVerificationMakesNoBackup() throws IOException {
		when(configLoader.verify(rawKey, Constants.VAULT_VERSION)).thenThrow(VaultKeyInvalidException.class);
		Assertions.assertThrows(VaultKeyInvalidException.class, () -> inTest.create(provider, pathToVault, properties));
		backupHelperClass.verify(() -> BackupHelper.attemptBackup(configFilePath), Mockito.never());
	}

	@Test
	public void testCreateThrowsIOExceptionIfBackupAttemptThrowsOne() throws IOException {
		backupHelperClass.when(() -> BackupHelper.attemptBackup(configFilePath)).thenThrow(new IOException());
		Assertions.assertThrows(IOException.class,() -> inTest.create(provider, pathToVault, properties));
	}

	@Test
	public void testGetReturnsFileSystemForPathIfItExists() throws IOException, MasterkeyLoadingFailedException {
		CryptoFileSystemImpl fileSystem = inTest.create(provider, pathToVault, properties);

		Assertions.assertTrue(inTest.contains(fileSystem));
		Assertions.assertSame(cryptoFileSystem, inTest.get(pathToVault));
	}

	@Test
	public void testThrowsFileSystemNotFoundExceptionIfItDoesNotExists() {
		FileSystemNotFoundException e = Assertions.assertThrows(FileSystemNotFoundException.class, () -> {
			inTest.get(pathToVault);
		});
		MatcherAssert.assertThat(e.getMessage(), containsString(normalizedPathToVault.toString()));
	}

}
