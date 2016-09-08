package org.cryptomator.cryptofs;

import static java.lang.String.format;
import static org.cryptomator.cryptofs.CryptoFileSystemModule.cryptoFileSystemModule;
import static org.cryptomator.cryptofs.UncheckedThrows.allowUncheckedThrowsOf;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.inject.Inject;

@PerProvider
class CryptoFileSystems {

	private final CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent;

	private final ConcurrentMap<Path, CryptoFileSystem> fileSystems = new ConcurrentHashMap<>();

	@Inject
	public CryptoFileSystems(CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent) {
		this.cryptoFileSystemProviderComponent = cryptoFileSystemProviderComponent;
	}

	public CryptoFileSystem create(Path pathToVault, CryptoFileSystemProperties properties) throws IOException {
		Path normalizedPathToVault = pathToVault.toRealPath(); // TODO use real path or absolute path?
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

	public void remove(CryptoFileSystem cryptoFileSystem) {
		fileSystems.values().remove(cryptoFileSystem);
	}

	public boolean contains(CryptoFileSystem cryptoFileSystem) {
		return fileSystems.containsValue(cryptoFileSystem);
	}

	public CryptoFileSystem get(Path pathToVault) {
		try {
			Path normalizedPathToVault = pathToVault.toRealPath(); // TODO use real path or absolute path?
			return fileSystems.computeIfAbsent(normalizedPathToVault, key -> {
				throw new FileSystemNotFoundException(format("CryptoFileSystem at %s not initialized", pathToVault));
			});
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

}
