package org.cryptomator.cryptofs.fh;

import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

@OpenFileScoped
class ChunkIO {

	private final Set<FileChannel> readableChannels = ConcurrentHashMap.newKeySet();
	private final Set<FileChannel> writableChannels = ConcurrentHashMap.newKeySet();

	@Inject
	public ChunkIO() {
	}

	/**
	 * Makes the given channel a candidate to read (always) and write (only if writable) ciphertext from/to.
	 *
	 * @param channel
	 * @param writable
	 */
	public void registerChannel(FileChannel channel, boolean writable) {
		readableChannels.add(channel);
		if (writable) {
			writableChannels.add(channel);
		}
	}

	/**
	 * Informs the chunk cache that the given channel will be closed soon and can no longer be used to read or write ciphertext.
	 *
	 * @param channel
	 */
	public void unregisterChannel(FileChannel channel) {
		readableChannels.remove(channel);
		writableChannels.remove(channel);
	}

	int read(ByteBuffer dst, long position) throws IOException {
		return getReadableChannel().read(dst, position);
	}

	private FileChannel getReadableChannel() throws ClosedChannelException {
		return openChannel(readableChannels, NonReadableChannelException::new);
	}

	FileChannel getWritableChannel() throws ClosedChannelException {
		return openChannel(writableChannels, NonWritableChannelException::new);
	}

	private static FileChannel openChannel(Set<FileChannel> channels, Supplier<RuntimeException> noneRegistered) throws ClosedChannelException {
		if (channels.isEmpty()) {
			throw noneRegistered.get();
		}
		return channels.stream().filter(FileChannel::isOpen).findFirst().orElseThrow(ClosedChannelException::new); // an interrupt can close a channel that is still registered
	}

}
