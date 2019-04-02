package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.fh.OpenCryptoFileComponent;

import java.nio.file.Path;

@PerFileSystem
@Subcomponent(modules = {CryptoFileSystemModule.class})
interface CryptoFileSystemComponent {

	CryptoFileSystemImpl cryptoFileSystem();

	OpenCryptoFileComponent.Builder newOpenCryptoFileComponent();

	CryptoFileAttributeViewComponent.Builder newFileAttributeViewComponent();

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder provider(CryptoFileSystemProvider provider);

		@BindsInstance
		Builder pathToVault(@PathToVault Path pathToVault);

		@BindsInstance
		Builder properties(CryptoFileSystemProperties cryptoFileSystemProperties);

		CryptoFileSystemComponent build();
	}

}
