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

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder openOptions(EffectiveOpenOptions options);

		@BindsInstance
		Builder onClose(ChannelCloseListener listener);

		@BindsInstance
		Builder ciphertextChannel(FileChannel ciphertextChannel);

		@BindsInstance
		Builder mustWriteHeader(@MustWriteHeader boolean mustWriteHeader);

		@BindsInstance
		Builder fileHeader(FileHeader fileHeader);

		ChannelComponent build();
	}

}
