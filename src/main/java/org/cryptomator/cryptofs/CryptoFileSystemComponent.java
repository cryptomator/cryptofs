package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptolib.api.Cryptor;

import java.nio.file.Path;

@CryptoFileSystemScoped
@Subcomponent(modules = {CryptoFileSystemModule.class})
public interface CryptoFileSystemComponent {

	CryptoFileSystemImpl cryptoFileSystem();

	@Subcomponent.Factory
	interface Factory {
		CryptoFileSystemComponent create(@BindsInstance Cryptor cryptor, //
										 @BindsInstance VaultConfig vaultConfig, //
										 @BindsInstance CryptoFileSystemProvider provider, //
										 @BindsInstance @PathToVault Path pathToVault, //
										 @BindsInstance CryptoFileSystemProperties cryptoFileSystemProperties);
	}

}
