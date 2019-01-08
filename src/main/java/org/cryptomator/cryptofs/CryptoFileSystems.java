package org.cryptomator.cryptofs;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.lang.String.format;
import static org.cryptomator.cryptofs.UncheckedThrows.allowUncheckedThrowsOf;

@PerProvider
class CryptoFileSystems {

	private final CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent;

	private final ConcurrentMap<Path, CryptoFileSystemImpl> fileSystems = new ConcurrentHashMap<>();

	@Inject
	public CryptoFileSystems(CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent) {
		this.cryptoFileSystemProviderComponent = cryptoFileSystemProviderComponent;
	}

	public CryptoFileSystemImpl create(CryptoFileSystemProvider provider, Path pathToVault, CryptoFileSystemProperties properties) throws IOException {
		Path normalizedPathToVault = pathToVault.normalize();
		return allowUncheckedThrowsOf(IOException.class).from(() -> fileSystems.compute(normalizedPathToVault, (key, value) -> {
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
