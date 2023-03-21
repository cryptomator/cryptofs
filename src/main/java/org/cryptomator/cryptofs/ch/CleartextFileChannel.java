package org.cryptomator.cryptofs.ch;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.fh.BufferPool;
import org.cryptomator.cryptofs.fh.Chunk;
import org.cryptomator.cryptofs.fh.ChunkCache;
import org.cryptomator.cryptofs.fh.ExceptionsDuringWrite;
import org.cryptomator.cryptofs.fh.OpenFileModifiedDate;
import org.cryptomator.cryptofs.fh.OpenFileSize;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Supplier;

import static java.lang.Math.max;
import static java.lang.Math.min;

@ChannelScoped
public class CleartextFileChannel extends AbstractFileChannel {

	private static final Logger LOG = LoggerFactory.getLogger(CleartextFileChannel.class);

	private final FileChannel ciphertextFileChannel;
	private final FileHeader fileHeader;
	private final Cryptor cryptor;
	private final ChunkCache chunkCache;
	private final BufferPool bufferPool;
	private final EffectiveOpenOptions options;
	private final AtomicLong fileSize;
	private final AtomicReference<Instant> lastModified;
	private final Supplier<BasicFileAttributeView> attrViewProvider;
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final ChannelCloseListener closeListener;
	private final CryptoFileSystemStats stats;
	private final AtomicBoolean mustWriteHeader;

	@Inject
	public CleartextFileChannel(FileChannel ciphertextFileChannel, FileHeader fileHeader, @MustWriteHeader boolean mustWriteHeader, ReadWriteLock readWriteLock, Cryptor cryptor, ChunkCache chunkCache, BufferPool bufferPool, EffectiveOpenOptions options, @OpenFileSize AtomicLong fileSize, @OpenFileModifiedDate AtomicReference<Instant> lastModified, Supplier<BasicFileAttributeView> attrViewProvider, ExceptionsDuringWrite exceptionsDuringWrite, ChannelCloseListener closeListener, CryptoFileSystemStats stats) {
		super(readWriteLock);
		this.ciphertextFileChannel = ciphertextFileChannel;
		this.fileHeader = fileHeader;
		this.cryptor = cryptor;
		this.chunkCache = chunkCache;
		this.bufferPool = bufferPool;
		this.options = options;
		this.fileSize = fileSize;
		this.lastModified = lastModified;
		this.attrViewProvider = attrViewProvider;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.closeListener = closeListener;
		this.stats = stats;
		if (options.append()) {
			position = fileSize.get();
		}
		this.mustWriteHeader = new AtomicBoolean(mustWriteHeader);
		if (options.createNew() || options.create()) {
			lastModified.compareAndSet(Instant.EPOCH, Instant.now());
		}
	}

	@Override
	public long size() throws IOException {
		assertOpen();
		return fileSize.get();
	}

	@Override
	protected boolean isWritable() {
		return options.writable();
	}

	@Override
	protected boolean isReadable() {
		return options.readable();
	}

	@Override
	protected int readLocked(ByteBuffer dst, long position) throws IOException {
		int origLimit = dst.limit();
		long limitConsideringEof = fileSize.get() - position;
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
			try (var chunk = chunkCache.getChunk(chunkIndex)) {
				ByteBuffer data = chunk.data().duplicate().position(offsetInChunk);
				int len = min(dst.remaining(), data.remaining()); // known to fit in int, because second argument is int
				dst.put(data.limit(data.position() + len));
				read += len;
			}
		}
		dst.limit(origLimit);
		stats.addBytesRead(read);
		return read;
	}

	@Override
	protected int writeLocked(ByteBuffer src, long position) throws IOException {
		long oldFileSize = fileSize.get();
		long written;
		if (position > oldFileSize) {
			// we need to fill the gap:
			long gapLen = position - oldFileSize;
			final ByteSource byteSource = ByteSource.repeatingZeroes(gapLen).followedBy(src); // prepend zeros to the original src
			written = writeLockedInternal(byteSource, oldFileSize) - gapLen; // fill the gap by beginning to write from old EOF
		} else {
			final ByteSource byteSource = ByteSource.from(src);
			written = writeLockedInternal(byteSource, position);
		}
		assert written <= src.capacity();
		return (int) written;
	}

	private long writeLockedInternal(ByteSource src, long position) throws IOException {
		Preconditions.checkArgument(position <= fileSize.get());

		writeHeaderIfNeeded();

		int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
		long written = 0;
		while (src.hasRemaining()) {
			long currentPosition = position + written;
			long chunkIndex = currentPosition / cleartextChunkSize; // floor by int-truncation
			assert chunkIndex >= 0;
			int offsetInChunk = (int) (currentPosition % cleartextChunkSize); // known to fit in int, because cleartextChunkSize is int
			assert offsetInChunk < cleartextChunkSize;
			int len = (int) min(src.remaining(), cleartextChunkSize - offsetInChunk); // known to fit in int, because second argument is int
			assert len <= cleartextChunkSize;
			if (offsetInChunk == 0 && len == cleartextChunkSize) {
				// complete chunk, no need to load and decrypt from file
				ByteBuffer cleartextChunkData = bufferPool.getCleartextBuffer();
				src.copyTo(cleartextChunkData);
				cleartextChunkData.flip();
				chunkCache.putChunk(chunkIndex, cleartextChunkData).close(); // TODO can we recycle cleartextChunkData (note: depends on branch in putChunk)?
			} else {
				/*
				 * TODO performance:
				 * We don't actually need to read the current data into the cache.
				 * It would suffice if store the written data and do reading when storing the chunk.
				 */
				try (Chunk chunk = chunkCache.getChunk(chunkIndex)) {
					chunk.data().limit(Math.max(chunk.data().limit(), offsetInChunk + len)); // increase limit (if needed)
					src.copyTo(chunk.data().duplicate().position(offsetInChunk)); // work on duplicate using correct offset
					chunk.dirty().set(true);
				}
			}
			written += len;
		}
		long minSize = position + written;
		long newSize = fileSize.updateAndGet(size -> max(minSize, size));
		assert newSize >= minSize;
		lastModified.set(Instant.now());
		if (options.syncData()) {
			forceInternal(options.syncDataAndMetadata());
		}
		stats.addBytesWritten(written);
		return written;
	}

	private void writeHeaderIfNeeded() throws IOException {
		if (mustWriteHeader.getAndSet(false)) {
			LOG.trace("{} - Writing file header.", this);
			ByteBuffer encryptedHeader = cryptor.fileHeaderCryptor().encryptHeader(fileHeader);
			ciphertextFileChannel.write(encryptedHeader, 0);
		}
	}

	@Override
	protected void truncateLocked(long newSize) throws IOException {
		Preconditions.checkArgument(newSize >= 0);
		if (newSize < fileSize.get()) {
			int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
			long indexOfLastChunk = (newSize + cleartextChunkSize - 1) / cleartextChunkSize - 1;
			int sizeOfIncompleteChunk = (int) (newSize % cleartextChunkSize); // known to fit in int, because cleartextChunkSize is int
			if (sizeOfIncompleteChunk > 0) {
				try (var chunk = chunkCache.getChunk(indexOfLastChunk)) {
					chunk.data().limit(sizeOfIncompleteChunk);
					chunk.dirty().set(true);
				}
			}
			long ciphertextFileSize = cryptor.fileHeaderCryptor().headerSize() + cryptor.fileContentCryptor().ciphertextSize(newSize);
			chunkCache.flush();
			chunkCache.invalidateAll(); // make sure no chunks _after_ newSize exist that would otherwise be written during the next cache eviction
			ciphertextFileChannel.truncate(ciphertextFileSize);
			position = min(newSize, position);
			fileSize.set(newSize);
			lastModified.set(Instant.now());
		}
	}

	@Override
	public void force(boolean metaData) throws IOException {
		assertOpen();
		forceInternal(metaData);
	}

	private void forceInternal(boolean metaData) throws IOException {
		flush();
		ciphertextFileChannel.force(metaData);
		if (metaData) {
			persistLastModified();
		}
	}

	/**
	 * Writes in-memory contents to the ciphertext file
	 * @throws IOException
	 */
	private void flush() throws IOException {
		if (isWritable()) {
			writeHeaderIfNeeded();
			chunkCache.flush();
			exceptionsDuringWrite.throwIfPresent();
		}
	}

	/**
	 * Corrects the last modified and access date due to possible cache invalidation (i.e. write operation!)
	 *
	 * @throws IOException
	 */
	private void persistLastModified() throws IOException {
		FileTime lastModifiedTime = isWritable() ? FileTime.from(lastModified.get()) : null;
		FileTime lastAccessTime = FileTime.from(Instant.now());
		attrViewProvider.get().setTimes(lastModifiedTime, lastAccessTime, null);
	}

	@Override
	public MappedByteBuffer map(MapMode mode, long position, long size) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FileLock lock(long pos, long size, boolean shared) throws IOException {
		assertOpen();
		if (shared && !options.readable()) {
			throw new NonReadableChannelException(); // shared lock only available on readable channel
		} else if (!shared && !options.writable()) {
			throw new NonWritableChannelException(); // exclusive lock only available on writable channel
		}
		long beginOfFirstChunk = beginOfChunk(pos);
		long beginOfLastChunk = beginOfChunk(pos + size);
		final FileLock ciphertextLock;
		if (beginOfFirstChunk == Long.MAX_VALUE || beginOfLastChunk == Long.MAX_VALUE) {
			ciphertextLock = ciphertextFileChannel.lock(0l, Long.MAX_VALUE, shared);
		} else {
			long endOfLastChunk = beginOfLastChunk + cryptor.fileContentCryptor().ciphertextChunkSize();
			ciphertextLock = ciphertextFileChannel.lock(beginOfFirstChunk, endOfLastChunk - beginOfFirstChunk, shared);
		}
		return new CleartextFileLock(this, ciphertextLock, pos, size);
	}

	@Override
	public FileLock tryLock(long pos, long size, boolean shared) throws IOException {
		assertOpen();
		if (shared && !options.readable()) {
			throw new NonReadableChannelException(); // shared lock only available on readable channel
		} else if (!shared && !options.writable()) {
			throw new NonWritableChannelException(); // exclusive lock only available on writable channel
		}
		long beginOfFirstChunk = beginOfChunk(pos);
		long beginOfLastChunk = beginOfChunk(pos + size);
		final FileLock ciphertextLock;
		if (beginOfFirstChunk == Long.MAX_VALUE || beginOfLastChunk == Long.MAX_VALUE) {
			ciphertextLock = ciphertextFileChannel.tryLock(0l, Long.MAX_VALUE, shared);
		} else {
			long endOfLastChunk = beginOfLastChunk + cryptor.fileContentCryptor().ciphertextChunkSize();
			ciphertextLock = ciphertextFileChannel.tryLock(beginOfFirstChunk, endOfLastChunk - beginOfFirstChunk, shared);
		}
		if (ciphertextLock == null) {
			return null;
		} else {
			return new CleartextFileLock(this, ciphertextLock, pos, size);
		}
	}

	// visible for testing
	long beginOfChunk(long cleartextPos) {
		long maxCiphertextPayloadSize = Long.MAX_VALUE - cryptor.fileHeaderCryptor().headerSize();
		long maxChunks = maxCiphertextPayloadSize / cryptor.fileContentCryptor().ciphertextChunkSize();
		long chunk = cleartextPos / cryptor.fileContentCryptor().cleartextChunkSize();
		if (chunk > maxChunks) {
			return Long.MAX_VALUE;
		} else {
			return chunk * cryptor.fileContentCryptor().ciphertextChunkSize() + cryptor.fileHeaderCryptor().headerSize();
		}
	}

	@Override
	protected void implCloseChannel() throws IOException {
		try {
			flush();
			persistLastModified();
		} finally {
			super.implCloseChannel();
			closeListener.closed(this);
		}
	}
}
