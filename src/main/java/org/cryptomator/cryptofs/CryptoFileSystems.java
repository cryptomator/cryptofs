package org.cryptomator.cryptofs;

import static java.lang.String.format;
import static org.cryptomator.cryptofs.CryptoFileSystemModule.cryptoFileSystemModule;
import static org.cryptomator.cryptofs.UncheckedThrows.allowUncheckedThrowsOf;

import java.io.IOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.inject.Inject;

@PerProvider
class CryptoFileSystems {

	private final CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent;

	private final ConcurrentMap<Path, CryptoFileSystemImpl> fileSystems = new ConcurrentHashMap<>();

	@Inject
	public CryptoFileSystems(CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent) {
		this.cryptoFileSystemProviderComponent = cryptoFileSystemProviderComponent;
	}

	public CryptoFileSystemImpl create(Path pathToVault, CryptoFileSystemProperties properties) throws IOException {
		Path normalizedPathToVault = pathToVault.normalize();
		return allowUncheckedThrowsOf(IOException.class).from(() -> fileSystems.compute(normalizedPathToVault, (key, value) -> {
			if (value == null) {
				return cryptoFileSystemProviderComponent //
						.newCryptoFileSystemComponent(cryptoFileSystemModule() //
								.withPathToVault(key) //
								.withCryptoFileSystemProperties(properties) //
								.build()) //
						.cryptoFileSystem();
			} else {
				throw new FileSystemAlreadyExistsException();
			}
		}));
	}

	public void remove(CryptoFileSystemImpl cryptoFileSystem) {
		fileSystems.values().remove(cryptoFileSystem);
	}

	public boolean contains(CryptoFileSystemImpl cryptoFileSystem) {
		return fileSystems.containsValue(cryptoFileSystem);
	}

	public CryptoFileSystemImpl get(Path pathToVault) {
		Path normalizedPathToVault = pathToVault.normalize();
		return fileSystems.computeIfAbsent(normalizedPathToVault, key -> {
			throw new FileSystemNotFoundException(format("CryptoFileSystem at %s not initialized", pathToVault));
		});
	}

}
