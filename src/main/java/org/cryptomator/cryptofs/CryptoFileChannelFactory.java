package org.cryptomator.cryptofs;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;

@PerOpenFile
class CryptoFileChannelFactory {

	private final ConcurrentMap<CryptoFileChannel, CryptoFileChannel> channels = new ConcurrentHashMap<>();
	private volatile boolean closed = false;
	private final FinallyUtil finallyUtil;

	@Inject
	public CryptoFileChannelFactory(FinallyUtil finallyUtil) {
		this.finallyUtil = finallyUtil;
	}

	public CryptoFileChannel create(OpenCryptoFile openCryptoFile, EffectiveOpenOptions options) throws IOException {
		CryptoFileChannel channel = new CryptoFileChannel(openCryptoFile, options, channels::remove, finallyUtil);
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