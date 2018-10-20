package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;

import javax.inject.Inject;

@PerOpenFile
class CryptoFileChannelFactory {

	private final ConcurrentMap<CryptoFileChannel, CryptoFileChannel> channels = new ConcurrentHashMap<>();
	private volatile boolean closed = false;
	private final FinallyUtil finallyUtil;

	@Inject
	public CryptoFileChannelFactory(FinallyUtil finallyUtil) {
		this.finallyUtil = finallyUtil;
	}

	@SuppressWarnings("finally")
	public CryptoFileChannel create(OpenCryptoFile openCryptoFile, EffectiveOpenOptions options) throws IOException {
		CryptoFileChannel channel = new CryptoFileChannel(openCryptoFile, options, closed -> channels.remove(closed), finallyUtil);
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
		Stream<RunnableThrowingException<IOException>> closers = channels.keySet().stream().map(ch -> ch::close);
		finallyUtil.guaranteeInvocationOf(closers.iterator());
	}

}