package org.cryptomator.cryptofs;

import dagger.Module;
import dagger.Provides;

import javax.inject.Singleton;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Module(subcomponents = {CryptoFileSystemComponent.class})
public class CryptoFileSystemProviderModule {

	@Provides
	@Singleton
	public SecureRandom provideCSPRNG() {
		try {
			return SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("A strong algorithm must exist in every Java platform.", e);
		}
	}

}
