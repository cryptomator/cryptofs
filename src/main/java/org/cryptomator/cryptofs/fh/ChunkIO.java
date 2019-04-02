package org.cryptomator.cryptofs.fh;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

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

	long size() throws IOException {
		return getReadableChannel().size();
	}

	int read(ByteBuffer dst, long position) throws IOException {
		return getReadableChannel().read(dst, position);
	}

	int write(ByteBuffer src, long position) throws IOException {
		return getWritableChannel().write(src, position);
	}

	private FileChannel getReadableChannel() {
		Iterator<FileChannel> iter = readableChannels.iterator();
		if (iter.hasNext()) {
			return iter.next();
		} else {
			throw new NonReadableChannelException();
		}
	}

	private FileChannel getWritableChannel() {
		Iterator<FileChannel> iter = writableChannels.iterator();
		if (iter.hasNext()) {
			return iter.next();
		} else {
			throw new NonWritableChannelException();
		}
	}

}
