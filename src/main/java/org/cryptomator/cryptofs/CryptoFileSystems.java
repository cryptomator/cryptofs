package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.BackupHelper;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.lang.String.format;

@Singleton
class CryptoFileSystems {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoFileSystems.class);

	private final ConcurrentMap<Path, CryptoFileSystemImpl> fileSystems = new ConcurrentHashMap<>();
	private final CryptoFileSystemComponent.Factory cryptoFileSystemComponentFactory;
	private final SecureRandom csprng;

	@Inject
	public CryptoFileSystems(CryptoFileSystemComponent.Factory cryptoFileSystemComponentFactory, SecureRandom csprng) {
		this.cryptoFileSystemComponentFactory = cryptoFileSystemComponentFactory;
		this.csprng = csprng;
	}

	public CryptoFileSystemImpl create(CryptoFileSystemProvider provider, Path pathToVault, CryptoFileSystemProperties properties) throws IOException, MasterkeyLoadingFailedException {
		Path normalizedPathToVault = pathToVault.normalize();
		var token = readVaultConfigFile(normalizedPathToVault, properties);

		var configLoader = VaultConfig.decode(token);
		var keyId = configLoader.getKeyId();
		try (Masterkey key = properties.keyLoader().loadKey(keyId)) {
			var config = configLoader.verify(key.getEncoded(), Constants.VAULT_VERSION);
			backupVaultConfigFile(normalizedPathToVault, properties);
			var cryptor = CryptorProvider.forScheme(config.getCipherCombo()).provide(key.copy(), csprng);
			try {
				checkVaultRootExistence(pathToVault, cryptor);
				return fileSystems.compute(normalizedPathToVault, (path, fs) -> {
					if (fs == null) {
						return cryptoFileSystemComponentFactory.create(cryptor, config, provider, normalizedPathToVault, properties).cryptoFileSystem();
					} else {
						throw new FileSystemAlreadyExistsException();
					}
				});
			} catch (Exception e) { //on any exception, destroy the cryptor
				cryptor.destroy();
				throw e;
			}
		}
	}

	/**
	 * Checks if the vault has a content root folder. If not, an exception is raised.
	 *
	 * @param pathToVault Path to the vault root
	 * @param cryptor Cryptor object initialized with the correct masterkey
	 * @throws ContentRootMissingException If the existence of encrypted vault content root cannot be ensured
	 */
	private void checkVaultRootExistence(Path pathToVault, Cryptor cryptor) throws ContentRootMissingException {
		String dirHash = cryptor.fileNameCryptor().hashDirectoryId(Constants.ROOT_DIR_ID);
		Path vaultCipherRootPath = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(dirHash.substring(0, 2)).resolve(dirHash.substring(2));
		if (!Files.exists(vaultCipherRootPath)) {
			throw new ContentRootMissingException(vaultCipherRootPath);
		}
	}

	/**
	 * Attempts to read a vault config file
	 *
	 * @param pathToVault path to the vault's root
	 * @param properties properties used when attempting to construct a fs for this vault
	 * @return The contents of the file decoded in ASCII
	 * @throws IOException If the file could not be read
	 * @throws FileSystemNeedsMigrationException If the file doesn't exists, but a legacy masterkey file was found instead
	 */
	private String readVaultConfigFile(Path pathToVault, CryptoFileSystemProperties properties) throws IOException, FileSystemNeedsMigrationException {
		Path vaultConfigFile = pathToVault.resolve(properties.vaultConfigFilename());
		try {
			return Files.readString(vaultConfigFile, StandardCharsets.US_ASCII);
		} catch (NoSuchFileException e) {
			// TODO: remove this check and tell downstream users to check the vault dir structure before creating a CryptoFileSystemImpl
			@SuppressWarnings("deprecation") var masterkeyFilename = properties.masterkeyFilename();
			if (masterkeyFilename != null && Files.exists(pathToVault.resolve(masterkeyFilename))) {
				LOG.warn("Failed to read {}, but found {}}", vaultConfigFile, masterkeyFilename);
				throw new FileSystemNeedsMigrationException(pathToVault);
			} else {
				throw e;
			}
		}
	}

	/**
	 * Attempts to create a backup of the vault config or compares to an existing one.
	 *
	 * @param pathToVault path to the vault's root
	 * @param properties properties used when attempting to construct a fs for this vault
	 * @throws IOException If the config cannot be read
	 */
	private void backupVaultConfigFile(Path pathToVault, CryptoFileSystemProperties properties) throws IOException {
		Path vaultConfigFile = pathToVault.resolve(properties.vaultConfigFilename());
		BackupHelper.attemptBackup(vaultConfigFile);
	}

	public void remove(CryptoFileSystemImpl cryptoFileSystem) {
		fileSystems.values().remove(cryptoFileSystem);
	}

	public boolean contains(CryptoFileSystemImpl cryptoFileSystem) {
		return fileSystems.containsValue(cryptoFileSystem);
	}

	public CryptoFileSystemImpl get(Path pathToVault) {
		Path normalizedPathToVault = pathToVault.normalize();
		CryptoFileSystemImpl fs = fileSystems.get(normalizedPathToVault);
		if (fs == null) {
			throw new FileSystemNotFoundException(format("CryptoFileSystem at %s not initialized", normalizedPathToVault));
		} else {
			return fs;
		}
	}

}
