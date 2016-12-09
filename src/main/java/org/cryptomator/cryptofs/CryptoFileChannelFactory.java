package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.FinallyUtils.guaranteeInvocationOf;

import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.inject.Inject;

@PerOpenFile
class CryptoFileChannelFactory {

	private final ConcurrentMap<CryptoFileChannel, CryptoFileChannel> channels = new ConcurrentHashMap<>();
	private volatile boolean closed = false;

	@Inject
	public CryptoFileChannelFactory() {
	}

	@SuppressWarnings("finally")
	public CryptoFileChannel create(OpenCryptoFile openCryptoFile, EffectiveOpenOptions options) throws IOException {
		CryptoFileChannel channel = new CryptoFileChannel(openCryptoFile, options, closed -> channels.remove(closed));
		channels.put(channel, channel);
		if (closed) {
			try {
				channel.close();
			} finally {
				throw new ClosedFileSystemException();
			}
		}
		return channel;
	}

	public void close() throws IOException {
		closed = true;
		guaranteeInvocationOf( //
				channels.keySet().stream() //
						.map(channel -> (RunnableThrowingException<IOException>) () -> channel.close()) //
						.iterator());
	}

}