package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptolib.api.Cryptor;

import java.nio.file.Path;

@CryptoFileSystemScoped
@Subcomponent(modules = {CryptoFileSystemModule.class})
public interface CryptoFileSystemComponent {

	CryptoFileSystemImpl cryptoFileSystem();

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder cryptor(Cryptor cryptor);

		@BindsInstance
		Builder vaultConfig(VaultConfig vaultConfig);

		@BindsInstance
		Builder provider(CryptoFileSystemProvider provider);

		@BindsInstance
		Builder pathToVault(@PathToVault Path pathToVault);

		@BindsInstance
		Builder properties(CryptoFileSystemProperties cryptoFileSystemProperties);

		CryptoFileSystemComponent build();
	}

}
