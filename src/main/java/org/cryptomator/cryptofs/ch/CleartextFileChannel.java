package org.cryptomator.cryptofs.ch;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
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
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;

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
	private final ExceptionsDuringWrite exceptionsDuringWrite;

	private long position;

	@Inject
	public CleartextFileChannel(Lock lock, FileChannel ciphertextFileChannel, Cryptor cryptor, ChunkCache chunkCache, EffectiveOpenOptions options, @OpenFileSize AtomicLong fileSize, ExceptionsDuringWrite exceptionsDuringWrite) {
		this.lock = lock;
		this.ciphertextFileChannel = ciphertextFileChannel;
		this.cryptor = cryptor;
		this.chunkCache = chunkCache;
		this.options = options;
		this.fileSize = fileSize;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		updateFileSize();
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
	public int write(ByteBuffer src, final long position) throws IOException {
		assertOpen();
		assertWritable();
		boolean completed = false;
		try {
			beginBlocking();
			// grow file if position is beyond old EOF:
			final long fillBytes = max(0, position - fileSize.get());
			final ByteSource source = ByteSource.repeatingZeroes(fillBytes).followedBy(src);
			int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
			int written = 0;
			while (source.hasRemaining()) {
				long currentPosition = position + written;
				long chunkIndex = currentPosition / cleartextChunkSize; // floor by int-truncation
				assert chunkIndex >= 0;
				int offsetInChunk = (int) (currentPosition % cleartextChunkSize); // known to fit in int, because cleartextChunkSize is int
				int len = (int) min(source.remaining(), cleartextChunkSize - offsetInChunk); // known to fit in int, because second argument is int
				assert len <= cleartextChunkSize;
				if (offsetInChunk == 0 && len == cleartextChunkSize) {
					// complete chunk, no need to load and decrypt from file
					ChunkData chunkData = ChunkData.emptyWithSize(cleartextChunkSize);
					chunkData.copyData().from(source);
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
			long minSize = position + written - fillBytes;
			fileSize.updateAndGet(size -> max(minSize, size));
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
		}
	}
}
