package org.cryptomator.cryptofs.ch;


@FunctionalInterface
public interface ChannelCloseListener {

	void closed(CleartextFileChannel channel);

}