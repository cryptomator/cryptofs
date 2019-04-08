package org.cryptomator.cryptofs;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.lang.String.format;

@Singleton
class CryptoFileSystems {

	private final CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent;

	private final ConcurrentMap<Path, CryptoFileSystemImpl> fileSystems = new ConcurrentHashMap<>();

	@Inject
	public CryptoFileSystems(CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent) {
		this.cryptoFileSystemProviderComponent = cryptoFileSystemProviderComponent;
	}

	public CryptoFileSystemImpl create(CryptoFileSystemProvider provider, Path pathToVault, CryptoFileSystemProperties properties) throws IOException {
		try {
			Path normalizedPathToVault = pathToVault.normalize();
			return fileSystems.compute(normalizedPathToVault, (key, value) -> {
				if (value == null) {
					return cryptoFileSystemProviderComponent //
							.newCryptoFileSystemComponent() //
							.pathToVault(key) //
							.properties(properties) //
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
