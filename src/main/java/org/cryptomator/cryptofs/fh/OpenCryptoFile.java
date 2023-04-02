/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

@OpenFileScoped
public class OpenCryptoFile implements Closeable {

	private static final Logger LOG = LoggerFactory.getLogger(OpenCryptoFile.class);

	private final FileCloseListener listener;
	private final AtomicReference<Instant> lastModified;
	private final ChunkCache chunkCache;
	private final Cryptor cryptor;
	private final FileHeaderHolder headerHolder;
	private final ChunkIO chunkIO;
	private final AtomicReference<Path> currentFilePath;
	private final AtomicLong fileSize;
	private final OpenCryptoFileComponent component;
	private final ConcurrentMap<CleartextFileChannel, FileChannel> openChannels = new ConcurrentHashMap<>();

	@Inject
	public OpenCryptoFile(FileCloseListener listener, ChunkCache chunkCache, Cryptor cryptor, FileHeaderHolder headerHolder, ChunkIO chunkIO, @CurrentOpenFilePath AtomicReference<Path> currentFilePath, @OpenFileSize AtomicLong fileSize, @OpenFileModifiedDate AtomicReference<Instant> lastModified, OpenCryptoFileComponent component) {
		this.listener = listener;
		this.chunkCache = chunkCache;
		this.cryptor = cryptor;
		this.headerHolder = headerHolder;
		this.chunkIO = chunkIO;
		this.currentFilePath = currentFilePath;
		this.fileSize = fileSize;
		this.component = component;
		this.lastModified = lastModified;
	}

	/**
	 * Creates a new file channel with the given open options.
	 *
	 * @param options The options to use to open the file channel. For the most part these will be passed through to the ciphertext channel.
	 * @return A new file channel. Ideally used in a try-with-resource statement. If the channel is not properly closed, this OpenCryptoFile will stay open indefinite.
	 * @throws IOException
	 */
	public synchronized FileChannel newFileChannel(EffectiveOpenOptions options, FileAttribute<?>... attrs) throws IOException {
		Path path = currentFilePath.get();

		FileChannel ciphertextFileChannel = null;
		CleartextFileChannel cleartextFileChannel = null;
		try {
			ciphertextFileChannel = path.getFileSystem().provider().newFileChannel(path, options.createOpenOptionsForEncryptedFile(), attrs);
			initFileHeader(options, ciphertextFileChannel);
			if (options.truncateExisting()) {
				chunkCache.invalidateAll();
				ciphertextFileChannel.truncate(cryptor.fileHeaderCryptor().headerSize());
			}
			initFileSize(ciphertextFileChannel);
			cleartextFileChannel = component.newChannelComponent() //
					.create(ciphertextFileChannel, options, this::channelClosed) //
					.channel();
		} finally {
			if (cleartextFileChannel == null) { // i.e. something didn't work
				closeQuietly(ciphertextFileChannel);
				// is this the first file channel to be opened?
				if (openChannels.isEmpty()) {
					close(); // then also close the file again.
				}
			}
		}

		assert cleartextFileChannel != null; // otherwise there would have been an exception
		openChannels.put(cleartextFileChannel, ciphertextFileChannel);
		chunkIO.registerChannel(ciphertextFileChannel, options.writable());
		return cleartextFileChannel;
	}

	//TODO test
	private void initFileHeader(EffectiveOpenOptions options, FileChannel ciphertextFileChannel) throws IOException {
		if (headerHolder.get() == null) {
			//first file channel to file, no header present
			if (options.createNew() || (options.create() && ciphertextFileChannel.size() == 0)) {
				//file did not exist, create new header
				headerHolder.createNew();
			} else {
				//file must exist, load header from file
				headerHolder.loadExisting(ciphertextFileChannel);
			}
		}
	}

	private void closeQuietly(Closeable closeable) {
		if (closeable != null) {
			try {
				closeable.close();
			} catch (IOException e) {
				// no-op
			}
		}
	}

	/**
	 * Called by {@link #newFileChannel(EffectiveOpenOptions, FileAttribute[])} to determine the fileSize.
	 * <p>
	 * Before the size is initialized (i.e. before a channel has been created), {@link #size()} must not be called.
	 * <p>
	 * Initialization happens at most once per open file. Subsequent invocations are no-ops.
	 */
	private void initFileSize(FileChannel ciphertextFileChannel) throws IOException {
		if (fileSize.get() == -1l) {
			LOG.trace("First channel for this openFile. Initializing file size...");
			long cleartextSize = 0l;
			try {
				long ciphertextSize = ciphertextFileChannel.size();
				if (ciphertextSize > 0l) {
					long payloadSize = ciphertextSize - cryptor.fileHeaderCryptor().headerSize();
					cleartextSize = cryptor.fileContentCryptor().cleartextSize(payloadSize);
				}
			} catch (IllegalArgumentException e) {
				LOG.warn("Invalid cipher text file size. Assuming empty file.", e);
				assert cleartextSize == 0l;
			}
			fileSize.compareAndSet(-1l, cleartextSize);
		}
	}

	/**
	 * @return The size of the opened file. Note that the filesize is unknown until a {@link #newFileChannel(EffectiveOpenOptions, FileAttribute[])} is opened. In this case this method returns an empty optional.
	 */
	public Optional<Long> size() {
		long val = fileSize.get();
		if (val == -1l) {
			return Optional.empty();
		} else {
			return Optional.of(val);
		}
	}

	public FileTime getLastModifiedTime() {
		return FileTime.from(lastModified.get());
	}

	public void setLastModifiedTime(FileTime lastModifiedTime) {
		lastModified.set(lastModifiedTime.toInstant());
	}

	public Path getCurrentFilePath() {
		return currentFilePath.get();
	}

	public void setCurrentFilePath(Path currentFilePath) {
		this.currentFilePath.set(currentFilePath);
	}

	private synchronized void channelClosed(CleartextFileChannel cleartextFileChannel) throws IOException {
		try {
			FileChannel ciphertextFileChannel = openChannels.remove(cleartextFileChannel);
			if (ciphertextFileChannel != null) {
				chunkIO.unregisterChannel(ciphertextFileChannel);
				ciphertextFileChannel.close();
			}
		} finally {
			if (openChannels.isEmpty()) {
				close();
			}
		}
	}

	@Override
	public void close() {
		listener.close(currentFilePath.get(), this);
	}

	@Override
	public String toString() {
		return "OpenCryptoFile(path=" + currentFilePath.toString() + ")";
	}
}
