package org.cryptomator.cryptofs.ch;


import java.nio.channels.FileChannel;

@FunctionalInterface
public interface ChannelCloseListener {

	void closed(FileChannel ciphertextChannel);

}