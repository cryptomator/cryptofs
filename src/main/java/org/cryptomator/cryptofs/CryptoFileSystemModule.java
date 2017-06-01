package org.cryptomator.cryptofs;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.cryptomator.cryptofs.UncheckedThrows.rethrowUnchecked;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;

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
	@PerFileSystem
	public Cryptor provideCryptor(CryptorProvider cryptorProvider, @PathToVault Path pathToVault, CryptoFileSystemProperties properties) {
		return rethrowUnchecked(IOException.class).from(() -> {
			Path masterKeyPath = pathToVault.resolve(properties.masterkeyFilename());
			Path backupKeyPath = pathToVault.resolve(properties.masterkeyFilename() + Constants.MASTERKEY_BACKUP_SUFFIX);
			assert Files.exists(masterKeyPath); // since 1.3.0 a file system can only be created for existing vaults. initialization is done before.
			byte[] keyFileContents = Files.readAllBytes(masterKeyPath);
			Cryptor cryptor = cryptorProvider.createFromKeyFile(KeyFile.parse(keyFileContents), properties.passphrase(), Constants.VAULT_VERSION);
			Files.copy(masterKeyPath, backupKeyPath, REPLACE_EXISTING);
			return cryptor;
		});
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
