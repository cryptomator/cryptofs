package org.cryptomator.cryptofs.fh;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.ch.ChannelComponent;

import java.nio.file.Path;

@Subcomponent(modules = {OpenCryptoFileModule.class})
@OpenFileScoped
public interface OpenCryptoFileComponent {

	OpenCryptoFile openCryptoFile();

	ChannelComponent.Factory newChannelComponent();

	@Subcomponent.Factory
	interface Factory {

		OpenCryptoFileComponent create(@BindsInstance @OriginalOpenFilePaths ClearAndCipherPath clearAndCipherPath, //
									   @BindsInstance FileCloseListener onCloseListener);
	}

}
