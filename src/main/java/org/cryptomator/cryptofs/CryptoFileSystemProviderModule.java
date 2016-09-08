package org.cryptomator.cryptofs;

import org.cryptomator.cryptolib.CryptoLibModule;

import dagger.Module;
import dagger.Provides;

@Module(includes = CryptoLibModule.class)
class CryptoFileSystemProviderModule {

	private final CryptoFileSystemProvider cryptoFileSystemProvider;

	private CryptoFileSystemProviderModule(Builder builder) {
		this.cryptoFileSystemProvider = builder.cryptoFileSystemProvider;
	}

	@Provides
	@PerProvider
	public CryptoFileSystemProvider provideCryptoFileSystemProvider() {
		return cryptoFileSystemProvider;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {

		private CryptoFileSystemProvider cryptoFileSystemProvider;

		private Builder() {
		}

		public Builder withCrytpoFileSystemProvider(CryptoFileSystemProvider cryptoFileSystemProvider) {
			this.cryptoFileSystemProvider = cryptoFileSystemProvider;
			return this;
		}

		public CryptoFileSystemProviderModule build() {
			validate();
			return new CryptoFileSystemProviderModule(this);
		}

		private void validate() {
			if (cryptoFileSystemProvider == null) {
				throw new IllegalStateException("cryptoFileSystemProvider must be set");
			}
		}

	}

}
