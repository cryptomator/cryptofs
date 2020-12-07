package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;
import org.cryptomator.cryptolib.api.Cryptor;
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
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.lang.String.format;

@Singleton
class CryptoFileSystems {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoFileSystems.class);

	private final ConcurrentMap<Path, CryptoFileSystemImpl> fileSystems = new ConcurrentHashMap<>();
	private final CryptoFileSystemComponent.Builder cryptoFileSystemComponentBuilder; // sharing reusable builder via synchronized
	private final FileSystemCapabilityChecker capabilityChecker;
	private final SecureRandom csprng;

	@Inject
	public CryptoFileSystems(CryptoFileSystemComponent.Builder cryptoFileSystemComponentBuilder, FileSystemCapabilityChecker capabilityChecker, SecureRandom csprng) {
		this.cryptoFileSystemComponentBuilder = cryptoFileSystemComponentBuilder;
		this.capabilityChecker = capabilityChecker;
		this.csprng = csprng;
	}

	public CryptoFileSystemImpl create(CryptoFileSystemProvider provider, Path pathToVault, CryptoFileSystemProperties properties) throws IOException, MasterkeyLoadingFailedException {
		Path normalizedPathToVault = pathToVault.normalize();
		var token = readVaultConfigFile(normalizedPathToVault, properties);

		var configLoader = VaultConfig.decode(token);
		byte[] rawKey = new byte[0];
		try (Masterkey key = properties.keyLoader().loadKey(configLoader.getKeyId())) {
			rawKey = key.getEncoded();
			var config = configLoader.verify(rawKey, Constants.VAULT_VERSION);
			var adjustedProperties = adjustForCapabilities(pathToVault, properties);
			return fileSystems.compute(normalizedPathToVault, (path, fs) -> {
				if (fs == null) {
					return create(provider, normalizedPathToVault, adjustedProperties, key, config);
				} else {
					throw new FileSystemAlreadyExistsException();
				}
			});
		} finally {
			Arrays.fill(rawKey, (byte) 0x00);
		}
	}

	// synchronized access to non-threadsafe cryptoFileSystemComponentBuilder required
	private synchronized CryptoFileSystemImpl create(CryptoFileSystemProvider provider, Path pathToVault, CryptoFileSystemProperties properties, Masterkey masterkey, VaultConfig config) {
		Cryptor cryptor = config.getCipherCombo().getCryptorProvider(csprng).withKey(masterkey);
		return cryptoFileSystemComponentBuilder //
				.cryptor(cryptor) //
				.vaultConfig(config) //
				.pathToVault(pathToVault) //
				.properties(properties) //
				.provider(provider) //
				.build() //
				.cryptoFileSystem();
	}

	/**
	 * Attempts to read a vault config file
	 *
	 * @param pathToVault path to the vault's root
	 * @param properties  properties used when attempting to construct a fs for this vault
	 * @return The contents of the file decoded in ASCII
	 * @throws IOException                       If the file could not be read
	 * @throws FileSystemNeedsMigrationException If the file doesn't exists, but a legacy masterkey file was found instead
	 */
	private String readVaultConfigFile(Path pathToVault, CryptoFileSystemProperties properties) throws IOException, FileSystemNeedsMigrationException {
		Path vaultConfigFile = pathToVault.resolve(properties.vaultConfigFilename());
		try {
			return Files.readString(vaultConfigFile, StandardCharsets.US_ASCII);
		} catch (NoSuchFileException e) {
			Path masterkeyPath = pathToVault.resolve(properties.masterkeyFilename());
			if (Files.exists(masterkeyPath)) {
				LOG.warn("Failed to read {}, but found {}}", vaultConfigFile, masterkeyPath);
				throw new FileSystemNeedsMigrationException(pathToVault);
			} else {
				throw e;
			}
		}
	}

	private CryptoFileSystemProperties adjustForCapabilities(Path pathToVault, CryptoFileSystemProperties originalProperties) throws FileSystemCapabilityChecker.MissingCapabilityException {
		if (!originalProperties.readonly()) {
			try {
				capabilityChecker.assertWriteAccess(pathToVault);
				return originalProperties;
			} catch (FileSystemCapabilityChecker.MissingCapabilityException e) {
				capabilityChecker.assertReadAccess(pathToVault);
				LOG.warn("No write access to vault. Fallback to read-only access.");
				Set<CryptoFileSystemProperties.FileSystemFlags> flags = EnumSet.copyOf(originalProperties.flags());
				flags.add(CryptoFileSystemProperties.FileSystemFlags.READONLY);
				return CryptoFileSystemProperties.cryptoFileSystemPropertiesFrom(originalProperties).withFlags(flags).build();
			}
		} else {
			return originalProperties;
		}
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
