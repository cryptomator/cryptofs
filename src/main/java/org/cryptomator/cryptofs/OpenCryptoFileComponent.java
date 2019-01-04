package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Subcomponent;

import java.nio.file.Path;

@Subcomponent(modules = {OpenCryptoFileModule.class})
@PerOpenFile
interface OpenCryptoFileComponent {

	OpenCryptoFile openCryptoFile();

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder path(@OriginalOpenFilePath Path path);

		@BindsInstance
		Builder openOptions(EffectiveOpenOptions options);

		OpenCryptoFileComponent build();
	}

}
