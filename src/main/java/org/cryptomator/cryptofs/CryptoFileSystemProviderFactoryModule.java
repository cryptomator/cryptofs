package org.cryptomator.cryptofs;

import java.security.SecureRandom;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;

import dagger.Module;
import dagger.Provides;

@Module
class CryptoFileSystemProviderFactoryModule {

	@Provides
	@PerProvider
	public CryptorProvider provideCryptorProvider(SecureRandom secureRandom) {
		return new CryptorProviderImpl(secureRandom);
	}

}
