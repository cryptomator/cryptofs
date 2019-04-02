package org.cryptomator.cryptofs.ch;


import java.io.IOException;

@FunctionalInterface
public interface ChannelCloseListener {

	void closed(CleartextFileChannel channel) throws IOException;

}