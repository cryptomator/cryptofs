package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.attr.AttributeViewComponent;
import org.cryptomator.cryptofs.fh.OpenCryptoFileComponent;

import java.nio.file.Path;

@CryptoFileSystemScoped
@Subcomponent(modules = {CryptoFileSystemModule.class})
public interface CryptoFileSystemComponent {

	CryptoFileSystemImpl cryptoFileSystem();

	OpenCryptoFileComponent.Builder newOpenCryptoFileComponent();

	AttributeViewComponent.Builder newFileAttributeViewComponent();

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
