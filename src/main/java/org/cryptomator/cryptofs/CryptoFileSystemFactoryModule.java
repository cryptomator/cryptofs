package org.cryptomator.cryptofs;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.cryptomator.cryptofs.UncheckedThrows.rethrowUnchecked;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.cryptomator.cryptolib.api.CryptoLibVersion;
import org.cryptomator.cryptolib.api.CryptoLibVersion.Version;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;

import dagger.Module;
import dagger.Provides;

@Module
class CryptoFileSystemFactoryModule {

	@Provides
	@PerFileSystem
	public Cryptor provideCryptor(@CryptoLibVersion(Version.ONE) CryptorProvider cryptorProvider, @PathToVault Path pathToVault, CryptoFileSystemProperties properties) {
		return rethrowUnchecked(IOException.class).from(() -> {
			Path masterKeyPath = pathToVault.resolve(Constants.MASTERKEY_FILE_NAME);
			Path backupKeyPath = pathToVault.resolve(Constants.BACKUPKEY_FILE_NAME);
			Cryptor cryptor;
			if (Files.isRegularFile(masterKeyPath)) {
				byte[] keyFileContents = Files.readAllBytes(masterKeyPath);
				cryptor = cryptorProvider.createFromKeyFile(KeyFile.parse(keyFileContents), properties.passphrase(), Constants.VAULT_VERSION);
				Files.copy(masterKeyPath, backupKeyPath, REPLACE_EXISTING);
			} else {
				cryptor = cryptorProvider.createNew();
				byte[] keyFileContents = cryptor.writeKeysToMasterkeyFile(properties.passphrase(), Constants.VAULT_VERSION).serialize();
				Files.createDirectories(masterKeyPath.getParent());
				Files.write(masterKeyPath, keyFileContents, CREATE_NEW, WRITE);
			}
			return cryptor;
		});
	}

}
