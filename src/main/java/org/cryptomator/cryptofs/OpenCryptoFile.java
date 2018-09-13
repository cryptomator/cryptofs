/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.OpenCounter.OpenState;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static java.lang.Math.max;
import static java.lang.Math.min;
import static org.cryptomator.cryptofs.OpenCounter.OpenState.ALREADY_CLOSED;
import static org.cryptomator.cryptofs.OpenCounter.OpenState.WAS_OPEN;
import static org.cryptomator.cryptolib.Cryptors.ciphertextSize;

@PerOpenFile
class OpenCryptoFile {

	private final Cryptor cryptor;
	private final FileChannel channel;
	private final FileHeader header;
	private final ChunkCache chunkCache;
	private final AtomicLong size;
	private final Runnable onClose;
	private final OpenCounter openCounter;
	private final CryptoFileChannelFactory cryptoFileChannelFactory;
	private final CryptoFileSystemStats stats;
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final FinallyUtil finallyUtil;
	private final BasicFileAttributeView attributeView;
	private final AtomicBoolean headerWritten;

	private final AtomicReference<Instant> lastModified;

	@Inject
	public OpenCryptoFile(EffectiveOpenOptions options, Cryptor cryptor, FileChannel channel, FileHeader header, @OpenFileSize AtomicLong size, OpenCounter openCounter, CryptoFileChannelFactory cryptoFileChannelFactory,
						  ChunkCache chunkCache, @OpenFileOnCloseHandler Runnable onClose, CryptoFileSystemStats stats, ExceptionsDuringWrite exceptionsDuringWrite, FinallyUtil finallyUtil, BasicFileAttributeView attrView) {
		this.cryptor = cryptor;
		this.chunkCache = chunkCache;
		this.openCounter = openCounter;
		this.cryptoFileChannelFactory = cryptoFileChannelFactory;
		this.onClose = onClose;
		this.channel = channel;
		this.header = header;
		this.size = size;
		this.stats = stats;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.finallyUtil = finallyUtil;
		this.attributeView = attrView;
		this.headerWritten = new AtomicBoolean(false);
		this.lastModified = new AtomicReference<>();
		try {
			lastModified.set(attrView.readAttributes().lastModifiedTime().toInstant());
		} catch (IOException e) {
			lastModified.set(Instant.ofEpochSecond(0));
		}

	}

	public FileChannel newFileChannel(EffectiveOpenOptions options) throws IOException {
		return cryptoFileChannelFactory.create(this, options);
	}

	public synchronized int read(ByteBuffer dst, long position) throws IOException {
		int origLimit = dst.limit();
		long limitConsideringEof = size() - position;
		if (limitConsideringEof < 1) {
			return -1;
		}
		dst.limit((int) min(origLimit, limitConsideringEof));
		int read = 0;
		int payloadSize = cryptor.fileContentCryptor().cleartextChunkSize();
		while (dst.hasRemaining()) {
			long pos = position + read;
			long chunkIndex = pos / payloadSize; // floor by int-truncation
			int offsetInChunk = (int) (pos % payloadSize); // known to fit in int, because payloadSize is int
			int len = min(dst.remaining(), payloadSize - offsetInChunk); // known to fit in int, because second argument is int
			final ChunkData chunkData = chunkCache.get(chunkIndex);
			chunkData.copyDataStartingAt(offsetInChunk).to(dst);
			read += len;
		}
		dst.limit(origLimit);
		stats.addBytesRead(read);
		return read;
	}

	public synchronized long append(EffectiveOpenOptions options, ByteBuffer src) throws IOException {
		return write(options, src, size());
	}

	public synchronized int write(EffectiveOpenOptions options, ByteBuffer data, long offset) throws IOException {
		writeHeaderIfNecessary();
		long size = size();
		int written = data.remaining();
		if (size < offset) {
			// fill gap between size and offset with zeroes
			write(ByteSource.repeatingZeroes(offset - size).followedBy(data), size);
		} else {
			write(ByteSource.from(data), offset);
		}
		handleSync(options);
		stats.addBytesWritten(written);
		lastModified.set(Instant.now());
		return written;
	}

	private void writeHeaderIfNecessary() throws IOException {
		if (headerWritten.compareAndSet(false, true)) {
			channel.write(cryptor.fileHeaderCryptor().encryptHeader(header), 0);

		}
	}

	private void handleSync(EffectiveOpenOptions options) throws IOException {
		if (options.syncData()) {
			force(options.syncDataAndMetadata(), options);
		}
	}

	private void write(ByteSource source, long position) throws IOException {
		int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
		int written = 0;
		while (source.hasRemaining()) {
			long currentPosition = position + written;
			long chunkIndex = currentPosition / cleartextChunkSize; // floor by int-truncation
			int offsetInChunk = (int) (currentPosition % cleartextChunkSize); // known to fit in int, because cleartextChunkSize is int
			int len = (int) min(source.remaining(), cleartextChunkSize - offsetInChunk); // known to fit in int, because second argument is int
			long minSize = currentPosition + len;
			size.getAndUpdate(size -> max(minSize, size));
			if (len == cleartextChunkSize) {
				// complete chunk, no need to load and decrypt from file
				ChunkData chunkData = ChunkData.emptyWithSize(cleartextChunkSize);
				chunkData.copyDataStartingAt(offsetInChunk).from(source);
				chunkCache.set(chunkIndex, chunkData);
			} else {
				/*
				 * TODO performance:
				 * We don't actually need to read the current data into the cache.
				 * It would suffice if store the written data and do reading when storing the chunk.
				 */
				ChunkData chunkData = chunkCache.get(chunkIndex);
				chunkData.copyDataStartingAt(offsetInChunk).from(source);
			}
			written += len;
		}

	}

	public long size() {
		return size.get();
	}

	public FileTime getLastModifiedTime() {
		return FileTime.from(lastModified.get());
	}

	public void setLastModifiedTime(FileTime lastModifiedTime) {
		lastModified.set(lastModifiedTime.toInstant());
	}

	public synchronized void truncate(long size) throws IOException {
		long originalSize = this.size.getAndUpdate(current -> min(size, current));
		if (originalSize > size) {
			int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
			long indexOfLastChunk = (size + cleartextChunkSize - 1) / cleartextChunkSize - 1;
			int sizeOfIncompleteChunk = (int) (size % cleartextChunkSize); // known to fit in int, because cleartextChunkSize is int
			if (sizeOfIncompleteChunk > 0) {
				chunkCache.get(indexOfLastChunk).truncate(sizeOfIncompleteChunk);
			}
			long ciphertextFileSize = cryptor.fileHeaderCryptor().headerSize() + ciphertextSize(size, cryptor);
			channel.truncate(ciphertextFileSize);
		}
	}

	public synchronized void force(boolean metaData, EffectiveOpenOptions options) throws IOException {
		chunkCache.invalidateAll(); // TODO performance: write chunks but keep them cached
		if (options.writable()) {
			exceptionsDuringWrite.throwIfPresent();
		}
		channel.force(metaData);
		attributeView.setTimes(FileTime.from(lastModified.get()), null, null);
	}

	public FileLock lock(long position, long size, boolean shared) throws IOException {
		return channel.lock(position, size, shared);
	}

	public FileLock tryLock(long position, long size, boolean shared) throws IOException {
		return channel.tryLock(position, size, shared);
	}

	public void open(EffectiveOpenOptions openOptions) throws IOException {
		OpenState state = openCounter.countOpen();
		if (state == ALREADY_CLOSED) {
			throw new ClosedChannelException();
		} else if (state == WAS_OPEN && openOptions.createNew()) {
			throw new IOException("Failed to create new file. File exists.");
		}
	}

	public void close() throws IOException {
		cryptoFileChannelFactory.close();
	}

	public void close(EffectiveOpenOptions options) throws IOException {
		try {
			force(true, options);
		} finally {
			if (openCounter.countClose()) {
				finallyUtil.guaranteeInvocationOf(
						() -> onClose.run(),
						() -> channel.close(),
						() -> cryptor.destroy()
				);
			}
		}
	}

}
