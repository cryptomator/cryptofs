package org.cryptomator.cryptofs.ch;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.EffectiveOpenOptions;

import java.nio.channels.FileChannel;

@ChannelScoped
@Subcomponent
public interface ChannelComponent {

	CleartextFileChannel channel();

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder openOptions(EffectiveOpenOptions options);

		@BindsInstance
		Builder onClose(ChannelCloseListener listener);

		@BindsInstance
		Builder ciphertextChannel(FileChannel ciphertextChannel);

		ChannelComponent build();
	}

}
