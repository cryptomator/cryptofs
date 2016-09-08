package org.cryptomator.cryptofs;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;
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

	@Provides
	@PerProvider
	public SecureRandom provideSecureRandom() {
		try {
			return new ReseedingSecureRandom(SecureRandom.getInstanceStrong(), SecureRandom.getInstance("SHA1PRNG"), 1 << 30, 55);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Java platform is required to support a strong SecureRandom and SHA1PRNG SecureRandom.", e);
		}
	}

}
