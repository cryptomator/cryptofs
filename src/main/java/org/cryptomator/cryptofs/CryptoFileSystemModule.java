package org.cryptomator.cryptofs;

import java.nio.file.Path;

import dagger.Module;
import dagger.Provides;

@Module
class CryptoFileSystemModule {

	private final Path pathToVault;
	private final CryptoFileSystemProperties cryptoFileSystemProperties;

	private CryptoFileSystemModule(Builder builder) {
		this.pathToVault = builder.pathToVault;
		this.cryptoFileSystemProperties = builder.cryptoFileSystemProperties;
	}

	@Provides
	@PathToVault
	@PerFileSystem
	public Path providePathToVault() {
		return pathToVault;
	}

	@Provides
	@PerFileSystem
	public CryptoFileSystemProperties provideCryptoFileSystemProperties() {
		return cryptoFileSystemProperties;
	}

	public static Builder cryptoFileSystemModule() {
		return new Builder();
	}

	public static class Builder {

		private Path pathToVault;
		private CryptoFileSystemProperties cryptoFileSystemProperties;

		private Builder() {
		}

		public Builder withPathToVault(Path pathToVault) {
			this.pathToVault = pathToVault;
			return this;
		}

		public Builder withCryptoFileSystemProperties(CryptoFileSystemProperties cryptoFileSystemProperties) {
			this.cryptoFileSystemProperties = cryptoFileSystemProperties;
			return this;
		}

		public CryptoFileSystemModule build() {
			validate();
			return new CryptoFileSystemModule(this);
		}

		private void validate() {
			if (pathToVault == null) {
				throw new IllegalStateException("pathToVault must be set");
			}
			if (cryptoFileSystemProperties == null) {
				throw new IllegalStateException("cryptoFileSystemProperties must be set");
			}
		}

	}

}
