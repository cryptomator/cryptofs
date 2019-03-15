package org.cryptomator.cryptofs.ch;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.OpenFileModifiedDate;
import org.cryptomator.cryptofs.OpenFileSize;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.function.Supplier;

import static java.lang.Math.max;
import static java.lang.Math.min;
import static org.cryptomator.cryptolib.Cryptors.ciphertextSize;

@ChannelScoped
public class CleartextFileChannel extends AbstractFileChannel {

	private static final Logger LOG = LoggerFactory.getLogger(CleartextFileChannel.class);

	private final Lock lock;
	private final FileChannel ciphertextFileChannel;
	private final Cryptor cryptor;
	private final ChunkCache chunkCache;
	private final EffectiveOpenOptions options;
	private final AtomicLong fileSize;
	private final AtomicReference<Instant> lastModified;
	private final Supplier<BasicFileAttributeView> attrViewProvider;
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final ChannelCloseListener closeListener;

	private long position;

	@Inject
	public CleartextFileChannel(Lock lock, FileChannel ciphertextFileChannel, Cryptor cryptor, ChunkCache chunkCache, EffectiveOpenOptions options, @OpenFileSize AtomicLong fileSize, @OpenFileModifiedDate AtomicReference<Instant> lastModified, Supplier<BasicFileAttributeView> attrViewProvider, ExceptionsDuringWrite exceptionsDuringWrite, ChannelCloseListener closeListener) {
		this.lock = lock;
		this.ciphertextFileChannel = ciphertextFileChannel;
		this.cryptor = cryptor;
		this.chunkCache = chunkCache;
		this.options = options;
		this.fileSize = fileSize;
		this.lastModified = lastModified;
		this.attrViewProvider = attrViewProvider;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.closeListener = closeListener;
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
	protected boolean isWritable() {
		return options.writable();
	}

	@Override
	protected boolean isReadable() {
		return options.readable();
	}

	@Override
	public int read(ByteBuffer dst) throws IOException {
		int read = read(dst, position);
		if (read != -1) {
			position += read;
		}
		return read;
	}

	@Override
	public int read(ByteBuffer dst, long position) throws IOException {
		assertOpen();
		assertReadable();
		boolean completed = false;
		try {
			beginBlocking();
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
			// stats.addBytesRead(read); // TODO
			completed = true;
			return read;
		} finally {
			endBlocking(completed);
		}
	}

	@Override
	public int write(ByteBuffer src) throws IOException {
		int written = write(src, position);
		position += written;
		return written;
	}

	@Override
	public int write(ByteBuffer src, long position) throws IOException {
		assertOpen();
		assertWritable();

		long oldFileSize = fileSize.get();
		if (position > oldFileSize) {
			// we need to fill the gap:
			long gapLen = position - oldFileSize;
			final ByteSource byteSource = ByteSource.repeatingZeroes(gapLen).followedBy(src); // prepend zeros to the original src
			return writeInternal(byteSource, oldFileSize); // fill the gap by beginning to write from old EOF
		} else {
			final ByteSource byteSource = ByteSource.from(src);
			return writeInternal(byteSource, position);
		}
	}

	private int writeInternal(ByteSource src, long position) throws IOException {
		Preconditions.checkArgument(position <= fileSize.get());
		assertOpen();
		assertWritable();
		boolean completed = false;
		try {
			beginBlocking();
			int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
			int written = 0;
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
			completed = true;
			return written;
		} finally {
			endBlocking(completed);
		}
	}

	@Override
	public long position() throws IOException {
		assertOpen();
		return position;
	}

	@Override
	public FileChannel position(long newPosition) throws IOException {
		Preconditions.checkArgument(newPosition >= 0);
		assertOpen();
		position = newPosition;
		return this;
	}

	@Override
	public long size() throws IOException {
		assertOpen();
		return fileSize.get();
	}

	@Override
	public FileChannel truncate(long newSize) throws IOException {
		Preconditions.checkArgument(newSize >= 0);
		assertOpen();
		assertWritable();
		boolean completed = false;
		try {
			beginBlocking();
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
			completed = true;
			return this;
		} finally {
			endBlocking(completed);
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
		}
		ciphertextFileChannel.force(metaData);
		attrViewProvider.get().setTimes(FileTime.from(lastModified.get()), null, null);
	}

	@Override
	public MappedByteBuffer map(MapMode mode, long position, long size) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FileLock lock(long position, long size, boolean shared) throws IOException {
		assertOpen();
		return null; // TODO
	}

	@Override
	public FileLock tryLock(long position, long size, boolean shared) throws IOException {
		assertOpen();
		return null; // TODO
	}

	@Override
	protected void implCloseChannel() throws IOException {
		try {
			forceInternal(true);
		} finally {
			super.implCloseChannel();
			lock.unlock();
			closeListener.closed(this);
		}
	}
}
