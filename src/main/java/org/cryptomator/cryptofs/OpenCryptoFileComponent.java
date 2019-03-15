package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.ch.ChannelComponent;

import java.nio.file.Path;

@Subcomponent(modules = {OpenCryptoFileModule.class})
@PerOpenFile
interface OpenCryptoFileComponent {

	OpenCryptoFile openCryptoFile();

	ChannelComponent.Builder newChannelComponent();

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder path(@OriginalOpenFilePath Path path);

		OpenCryptoFileComponent build();
	}

}
