package org.cryptomator.cryptofs.common;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;

import java.nio.channels.ByteChannel;

public class EncryptedChannels {

	private EncryptedChannels() {}


	public static DecryptingReadableByteChannel wrapDecryptionAround(ByteChannel channel, Cryptor cryptor) {
		return new DecryptingReadableByteChannel(channel, cryptor, true);
	}

	public static EncryptingWritableByteChannel wrapEncryptionAround(ByteChannel channel, Cryptor cryptor) {
		return new EncryptingWritableByteChannel(channel, cryptor);
	}

}
