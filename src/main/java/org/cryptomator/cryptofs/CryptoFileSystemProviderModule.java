package org.cryptomator.cryptofs;

import java.util.Objects;

import org.cryptomator.cryptolib.api.CryptorProvider;

import dagger.Module;
import dagger.Provides;

@Module
class CryptoFileSystemProviderModule {

	private final CryptoFileSystemProvider cryptoFileSystemProvider;
	private final CryptorProvider cryptorProvider;

	public CryptoFileSystemProviderModule(CryptoFileSystemProvider cryptoFileSystemProvider, CryptorProvider cryptorProvider) {
		this.cryptoFileSystemProvider = Objects.requireNonNull(cryptoFileSystemProvider);
		this.cryptorProvider = cryptorProvider;
	}

	@Provides
	@PerProvider
	public CryptoFileSystemProvider provideCryptoFileSystemProvider() {
		return cryptoFileSystemProvider;
	}

	@Provides
	@PerProvider
	public CryptorProvider provideCryptorProvider() {
		return cryptorProvider;
	}

}
