package org.cryptomator.cryptofs.ch;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.EffectiveOpenOptions;

import java.nio.channels.FileChannel;
import java.util.function.Consumer;

@ChannelScoped
@Subcomponent
public interface ChannelComponent {

	CleartextFileChannel channel();

	@Subcomponent.Factory
	interface Factory {

		ChannelComponent create(@BindsInstance FileChannel ciphertextChannel, //
								@BindsInstance EffectiveOpenOptions options, //
								@BindsInstance Consumer<FileChannel> closeListener); //
	}

}
