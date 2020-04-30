package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Path;
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

	@Inject
	public CryptoFileSystems(CryptoFileSystemComponent.Builder cryptoFileSystemComponentBuilder, FileSystemCapabilityChecker capabilityChecker) {
		this.cryptoFileSystemComponentBuilder = cryptoFileSystemComponentBuilder;
		this.capabilityChecker = capabilityChecker;
	}

	public synchronized CryptoFileSystemImpl create(CryptoFileSystemProvider provider, Path pathToVault, CryptoFileSystemProperties properties) throws IOException {
		try {
			Path normalizedPathToVault = pathToVault.normalize();
			CryptoFileSystemProperties adjustedProperites = adjustForCapabilities(normalizedPathToVault, properties);
			return fileSystems.compute(normalizedPathToVault, (key, value) -> {
				if (value == null) {
					return cryptoFileSystemComponentBuilder //
							.pathToVault(key) //
							.properties(adjustedProperites) //
							.provider(provider) //
							.build() //
							.cryptoFileSystem();
				} else {
					throw new FileSystemAlreadyExistsException();
				}
			});
		} catch (UncheckedIOException e) {
			throw new IOException("Error during file system creation.", e);
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
			throw new FileSystemNotFoundException(format("CryptoFileSystem at %s not initialized", pathToVault));
		} else {
			return fs;
		}
	}

}
