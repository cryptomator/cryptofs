package org.cryptomator.cryptofs.ch;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.fh.ByteSource;
import org.cryptomator.cryptofs.fh.ChunkCache;
import org.cryptomator.cryptofs.fh.ChunkData;
import org.cryptomator.cryptofs.fh.ExceptionsDuringWrite;
import org.cryptomator.cryptofs.fh.OpenFileModifiedDate;
import org.cryptomator.cryptofs.fh.OpenFileSize;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Supplier;

import static java.lang.Math.max;
import static java.lang.Math.min;
import static org.cryptomator.cryptolib.Cryptors.ciphertextSize;

@ChannelScoped
public class CleartextFileChannel extends AbstractFileChannel {

	private static final Logger LOG = LoggerFactory.getLogger(CleartextFileChannel.class);

	private final FileChannel ciphertextFileChannel;
	private final Cryptor cryptor;
	private final ChunkCache chunkCache;
	private final EffectiveOpenOptions options;
	private final AtomicLong fileSize;
	private final AtomicReference<Instant> lastModified;
	private final Supplier<BasicFileAttributeView> attrViewProvider;
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final ChannelCloseListener closeListener;
	private final CryptoFileSystemStats stats;

	@Inject
	public CleartextFileChannel(FileChannel ciphertextFileChannel, ReadWriteLock readWriteLock, Cryptor cryptor, ChunkCache chunkCache, EffectiveOpenOptions options, @OpenFileSize AtomicLong fileSize, @OpenFileModifiedDate AtomicReference<Instant> lastModified, Supplier<BasicFileAttributeView> attrViewProvider, ExceptionsDuringWrite exceptionsDuringWrite, ChannelCloseListener closeListener, CryptoFileSystemStats stats) {
		super(readWriteLock);
		this.ciphertextFileChannel = ciphertextFileChannel;
		this.cryptor = cryptor;
		this.chunkCache = chunkCache;
		this.options = options;
		this.fileSize = fileSize;
		this.lastModified = lastModified;
		this.attrViewProvider = attrViewProvider;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.closeListener = closeListener;
		this.stats = stats;
		updateFileSize();
		if (options.append()) {
			position = fileSize.get();
		}
	}

	private void updateFileSize() {
		try {
			long ciphertextSize = ciphertextFileChannel.size();
			if (ciphertextSize == 0l) {
				fileSize.set(0l);
			} else {
				long cleartextSize = Cryptors.cleartextSize(ciphertextSize - cryptor.fileHeaderCryptor().headerSize(), cryptor);
				fileSize.set(cleartextSize);
			}
		} catch (IllegalArgumentException e) {
			LOG.warn("Invalid cipher text file size.", e);
			fileSize.set(0l);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
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
			int len = min(dst.remaining(), payloadSize - offsetInChunk); // known to fit in int, because second argument is int
			final ChunkData chunkData = chunkCache.get(chunkIndex);
			chunkData.copyDataStartingAt(offsetInChunk).to(dst);
			read += len;
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
			final ByteSource byteSource = ByteSource.undefinedNoise(gapLen).followedBy(src); // prepend zeros to the original src
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

		int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
		long written = 0;
		while (src.hasRemaining()) {
			long currentPosition = position + written;
			long chunkIndex = currentPosition / cleartextChunkSize; // floor by int-truncation
			assert chunkIndex >= 0;
			int offsetInChunk = (int) (currentPosition % cleartextChunkSize); // known to fit in int, because cleartextChunkSize is int
			int len = (int) min(src.remaining(), cleartextChunkSize - offsetInChunk); // known to fit in int, because second argument is int
			assert len <= cleartextChunkSize;
			if (offsetInChunk == 0 && len == cleartextChunkSize) {
				// complete chunk, no need to load and decrypt from file
				ChunkData chunkData = ChunkData.emptyWithSize(cleartextChunkSize);
				chunkData.copyData().from(src);
				chunkCache.set(chunkIndex, chunkData);
			} else {
				/*
				 * TODO performance:
				 * We don't actually need to read the current data into the cache.
				 * It would suffice if store the written data and do reading when storing the chunk.
				 */
				ChunkData chunkData = chunkCache.get(chunkIndex);
				chunkData.copyDataStartingAt(offsetInChunk).from(src);
			}
			written += len;
		}
		long minSize = position + written;
		fileSize.updateAndGet(size -> max(minSize, size));
		lastModified.set(Instant.now());
		stats.addBytesWritten(written);
		return written;
	}

	@Override
	protected void truncateLocked(long newSize) throws IOException {
		Preconditions.checkArgument(newSize >= 0);
		if (newSize < fileSize.get()) {
			int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
			long indexOfLastChunk = (newSize + cleartextChunkSize - 1) / cleartextChunkSize - 1;
			int sizeOfIncompleteChunk = (int) (newSize % cleartextChunkSize); // known to fit in int, because cleartextChunkSize is int
			if (sizeOfIncompleteChunk > 0) {
				chunkCache.get(indexOfLastChunk).truncate(sizeOfIncompleteChunk);
			}
			long ciphertextFileSize = cryptor.fileHeaderCryptor().headerSize() + ciphertextSize(newSize, cryptor);
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
		if (isWritable()) {
			chunkCache.invalidateAll(); // TODO performance: write chunks but keep them cached
			exceptionsDuringWrite.throwIfPresent();
			attrViewProvider.get().setTimes(FileTime.from(lastModified.get()), null, null);
		}
		ciphertextFileChannel.force(metaData);
	}

	@Override
	public MappedByteBuffer map(MapMode mode, long position, long size) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FileLock lock(long position, long size, boolean shared) throws IOException {
		assertOpen();
		if (shared && !options.readable()) {
			throw new NonReadableChannelException(); // shared lock only available on readable channel
		} else if (!shared && !options.writable()) {
			throw new NonWritableChannelException(); // exclusive lock only available on writable channel
		}
		long firstChunk = position / cryptor.fileContentCryptor().cleartextChunkSize();
		long lastChunk = firstChunk + size / cryptor.fileContentCryptor().cleartextChunkSize();
		long ciphertextPosition = cryptor.fileHeaderCryptor().headerSize() + firstChunk * cryptor.fileContentCryptor().ciphertextChunkSize();
		long ciphertextSize = (lastChunk - firstChunk + 1) * cryptor.fileContentCryptor().ciphertextChunkSize();
		FileLock ciphertextLock = ciphertextFileChannel.lock(ciphertextPosition, ciphertextSize, shared);
		return new CleartextFileLock(this, ciphertextLock, position, size);
	}

	@Override
	public FileLock tryLock(long position, long size, boolean shared) throws IOException {
		assertOpen();
		if (shared && !options.readable()) {
			throw new NonReadableChannelException(); // shared lock only available on readable channel
		} else if (!shared && !options.writable()) {
			throw new NonWritableChannelException(); // exclusive lock only available on writable channel
		}
		long firstChunk = position / cryptor.fileContentCryptor().cleartextChunkSize();
		long lastChunk = firstChunk + size / cryptor.fileContentCryptor().cleartextChunkSize();
		long ciphertextPosition = cryptor.fileHeaderCryptor().headerSize() + firstChunk * cryptor.fileContentCryptor().ciphertextChunkSize();
		long ciphertextSize = (lastChunk - firstChunk + 1) * cryptor.fileContentCryptor().ciphertextChunkSize();
		FileLock ciphertextLock = ciphertextFileChannel.tryLock(ciphertextPosition, ciphertextSize, shared);
		if (ciphertextLock == null) {
			return null;
		} else {
			return new CleartextFileLock(this, ciphertextLock, position, size);
		}
	}

	@Override
	protected void implCloseChannel() throws IOException {
		try {
			forceInternal(true);
		} finally {
			super.implCloseChannel();
			closeListener.closed(this);
		}
	}
}
