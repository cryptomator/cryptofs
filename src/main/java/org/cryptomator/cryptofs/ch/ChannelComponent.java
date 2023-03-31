package org.cryptomator.cryptofs.ch;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptolib.api.FileHeader;

import java.nio.channels.FileChannel;

@ChannelScoped
@Subcomponent
public interface ChannelComponent {

	CleartextFileChannel channel();

	@Subcomponent.Factory
	interface Factory {

		ChannelComponent create(@BindsInstance FileChannel ciphertextChannel, //
								@BindsInstance EffectiveOpenOptions options, //
								@BindsInstance ChannelCloseListener listener); //
	}

}
