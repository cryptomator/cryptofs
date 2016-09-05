package org.cryptomator.cryptofs;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.cryptomator.cryptolib.common.ReseedingSecureRandom;

import dagger.Module;
import dagger.Provides;

@Module
class CryptoFileSystemProviderModule {

	private final CryptoFileSystemProvider cryptoFileSystemProvider;
	private final SecureRandom secureRandom;

	private CryptoFileSystemProviderModule(Builder builder) {
		this.cryptoFileSystemProvider = builder.cryptoFileSystemProvider;
		this.secureRandom = builder.secureRandom;
	}

	@Provides
	@PerProvider
	public CryptoFileSystemProvider provideCryptoFileSystemProvider() {
		return cryptoFileSystemProvider;
	}

	@Provides
	@PerProvider
	public SecureRandom provideSecureRandom() {
		return secureRandom;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {

		private CryptoFileSystemProvider cryptoFileSystemProvider;
		private SecureRandom secureRandom;

		private Builder() {
		}

		public Builder withCrytpoFileSystemProvider(CryptoFileSystemProvider cryptoFileSystemProvider) {
			this.cryptoFileSystemProvider = cryptoFileSystemProvider;
			return this;
		}

		public Builder withSecureRandom(SecureRandom secureRandom) {
			this.secureRandom = secureRandom;
			return this;
		}

		public CryptoFileSystemProviderModule build() {
			validate();
			prepare();
			return new CryptoFileSystemProviderModule(this);
		}

		private void prepare() {
			if (secureRandom == null) {
				secureRandom = defaultSecureRandom();
			}
		}

		private void validate() {
			if (cryptoFileSystemProvider == null) {
				throw new IllegalStateException("cryptoFileSystemProvider must be set");
			}
		}

	}

	private static SecureRandom defaultSecureRandom() {
		try {
			return new ReseedingSecureRandom(SecureRandom.getInstanceStrong(), SecureRandom.getInstance("SHA1PRNG"), 1 << 30, 55);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Java platform is required to support a strong SecureRandom and SHA1PRNG SecureRandom.", e);
		}
	}

}
