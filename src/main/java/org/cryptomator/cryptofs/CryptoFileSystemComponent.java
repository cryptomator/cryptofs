package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.attr.AttributeViewComponent;
import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;
import org.cryptomator.cryptofs.dir.DirectoryStreamComponent;
import org.cryptomator.cryptofs.fh.OpenCryptoFileComponent;

import java.nio.file.Path;
import java.util.Set;

@CryptoFileSystemScoped
@Subcomponent(modules = {CryptoFileSystemModule.class})
public interface CryptoFileSystemComponent {

	CryptoFileSystemImpl cryptoFileSystem();

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
