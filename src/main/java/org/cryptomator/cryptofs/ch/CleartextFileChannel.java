package org.cryptomator.cryptofs.ch;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.fh.BufferPool;
import org.cryptomator.cryptofs.fh.Chunk;
import org.cryptomator.cryptofs.fh.ChunkCache;
import org.cryptomator.cryptofs.fh.CurrentOpenFilePath;
import org.cryptomator.cryptofs.fh.ExceptionsDuringWrite;
import org.cryptomator.cryptofs.fh.FileHeaderHolder;
import org.cryptomator.cryptofs.fh.OpenFileModifiedDate;
import org.cryptomator.cryptofs.fh.OpenFileSize;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Consumer;

import static java.lang.Math.max;
import static java.lang.Math.min;

@ChannelScoped
public class CleartextFileChannel extends AbstractFileChannel {

	private static final Logger LOG = LoggerFactory.getLogger(CleartextFileChannel.class);

	private final FileChannel ciphertextFileChannel;
	private final FileHeaderHolder fileHeaderHolder;
	private final Cryptor cryptor;
	private final ChunkCache chunkCache;
	private final BufferPool bufferPool;
	private final EffectiveOpenOptions options;
	private final AtomicReference<Path> currentFilePath;
	private final AtomicLong fileSize;
	private final AtomicReference<Instant> lastModified;
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final Consumer<FileChannel> closeListener;
	private final CryptoFileSystemStats stats;

	@Inject
	public CleartextFileChannel(FileChannel ciphertextFileChannel, FileHeaderHolder fileHeaderHolder, ReadWriteLock readWriteLock, Cryptor cryptor, ChunkCache chunkCache, BufferPool bufferPool, EffectiveOpenOptions options, @OpenFileSize AtomicLong fileSize, @OpenFileModifiedDate AtomicReference<Instant> lastModified, @CurrentOpenFilePath AtomicReference<Path> currentPath, ExceptionsDuringWrite exceptionsDuringWrite, Consumer<FileChannel> closeListener, CryptoFileSystemStats stats) {
		super(readWriteLock);
		this.ciphertextFileChannel = ciphertextFileChannel;
		this.fileHeaderHolder = fileHeaderHolder;
		this.cryptor = cryptor;
		this.chunkCache = chunkCache;
		this.bufferPool = bufferPool;
		this.options = options;
		this.currentFilePath = currentPath;
		this.fileSize = fileSize;
		this.lastModified = lastModified;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.closeListener = closeListener;
		this.stats = stats;
		if (options.append()) {
			position = fileSize.get();
		}
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
				chunkCache.putChunk(chunkIndex, cleartextChunkData).close();
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
		if (fileHeaderHolder.headerIsPersisted().get()) {
			return;
		}
		LOG.trace("{} - Writing file header.", this);
		ciphertextFileChannel.write(fileHeaderHolder.getEncrypted(), 0);
		fileHeaderHolder.headerIsPersisted().set(true);
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
			chunkCache.invalidateStale(); // make sure no chunks _after_ newSize exist that would otherwise be written during the next cache eviction
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
	 *
	 * @throws IOException
	 */
	@VisibleForTesting
	void flush() throws IOException {
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
	@VisibleForTesting
	void persistLastModified() throws IOException {
		FileTime lastModifiedTime = isWritable() ? FileTime.from(lastModified.get()) : null;
		FileTime lastAccessTime = FileTime.from(Instant.now());
		var p = currentFilePath.get();
		if (p != null) {
			p.getFileSystem().provider()//
					.getFileAttributeView(p, BasicFileAttributeView.class)
					.setTimes(lastModifiedTime, lastAccessTime, null);
		}

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
		var closeActions = List.<CloseAction>of(this::flush, //
				super::implCloseChannel, //
				() -> closeListener.accept(ciphertextFileChannel),
				ciphertextFileChannel::close, //
				this::tryPersistLastModified);
		tryAll(closeActions.iterator());
	}

	private void tryPersistLastModified() {
		try {
			persistLastModified();
		} catch (NoSuchFileException nsfe) {
			//no-op, see https://github.com/cryptomator/cryptofs/issues/169
		} catch (IOException e) {
			LOG.warn("Failed to persist last modified timestamp for encrypted file: {}", e.getMessage());
		}
	}

	private void tryAll(Iterator<CloseAction> actions) throws IOException {
		if (actions.hasNext()) {
			try {
				actions.next().run();
			} finally {
				tryAll(actions);
			}
		}
	}

	@FunctionalInterface
	private interface CloseAction {

		void run() throws IOException;
	}

}
