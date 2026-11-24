package org.cryptomator.cryptofs.ch;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import jakarta.inject.Inject;
import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.event.FileIsInUseEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptofs.fh.BufferPool;
import org.cryptomator.cryptofs.fh.Chunk;
import org.cryptomator.cryptofs.fh.ChunkCache;
import org.cryptomator.cryptofs.fh.CiphertextFileKey;
import org.cryptomator.cryptofs.fh.CiphertextWriteGuard;
import org.cryptomator.cryptofs.fh.CurrentOpenFileCleartextPath;
import org.cryptomator.cryptofs.fh.CurrentOpenFilePath;
import org.cryptomator.cryptofs.fh.ExceptionsDuringWrite;
import org.cryptomator.cryptofs.fh.FileHeaderHolder;
import org.cryptomator.cryptofs.fh.OpenFileModifiedDate;
import org.cryptomator.cryptofs.fh.OpenFileSize;
import org.cryptomator.cryptofs.inuse.FileAlreadyInUseException;
import org.cryptomator.cryptofs.inuse.InUseManager;
import org.cryptomator.cryptofs.inuse.StubInUseManager;
import org.cryptomator.cryptofs.inuse.UseInfo;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.ReadableByteChannel;
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
	private final Consumer<FilesystemEvent> eventConsumer;
	private final CryptoFileSystemStats stats;
	private final InUseManager inUseManager;
	private final AtomicReference<CryptoPath> currentCleartextPath;
	private final CiphertextFileKey ciphertextFileKey;
	private final CiphertextWriteGuard writeGuard;

	@Inject
	public CleartextFileChannel(FileChannel ciphertextFileChannel, //
								FileHeaderHolder fileHeaderHolder, //
								ReadWriteLock readWriteLock, //
								Cryptor cryptor, //
								ChunkCache chunkCache, //
								BufferPool bufferPool, //
								EffectiveOpenOptions options, //
								@OpenFileSize AtomicLong fileSize, //
								@OpenFileModifiedDate AtomicReference<Instant> lastModified, //
								@CurrentOpenFilePath AtomicReference<Path> currentPath, //
								@CurrentOpenFileCleartextPath AtomicReference<CryptoPath> currentCleartextPath, //
								CiphertextFileKey ciphertextFileKey, //
								CiphertextWriteGuard writeGuard, //
								ExceptionsDuringWrite exceptionsDuringWrite, //
								Consumer<FileChannel> closeListener, //
								Consumer<FilesystemEvent> eventConsumer, //
								CryptoFileSystemStats stats, //
								InUseManager inUseManager) {
		super(readWriteLock);
		this.ciphertextFileChannel = ciphertextFileChannel;
		this.fileHeaderHolder = fileHeaderHolder;
		this.cryptor = cryptor;
		this.chunkCache = chunkCache;
		this.bufferPool = bufferPool;
		this.options = options;
		this.currentFilePath = currentPath;
		this.currentCleartextPath = currentCleartextPath;
		this.ciphertextFileKey = ciphertextFileKey;
		this.writeGuard = writeGuard;
		this.fileSize = fileSize;
		this.lastModified = lastModified;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.closeListener = closeListener;
		this.eventConsumer = eventConsumer;
		this.stats = stats;
		this.inUseManager = inUseManager;
		if (options.append()) {
			position = fileSize.get();
		}
		if (options.createNew() || options.create()) {
			lastModified.compareAndSet(Instant.EPOCH, Instant.now());
		}
	}

	@VisibleForTesting
	CleartextFileChannel(FileChannel ciphertextFileChannel, //
						 FileHeaderHolder fileHeaderHolder, //
						 ReadWriteLock readWriteLock, //
						 Cryptor cryptor, //
						 ChunkCache chunkCache, //
						 BufferPool bufferPool, //
						 EffectiveOpenOptions options, //
						 AtomicLong fileSize, //
						 AtomicReference<Instant> lastModified, //
						 AtomicReference<Path> currentPath, //
						 CiphertextWriteGuard writeGuard, //
						 ExceptionsDuringWrite exceptionsDuringWrite, //
						 Consumer<FileChannel> closeListener, //
						 CryptoFileSystemStats stats) {
		this(ciphertextFileChannel, fileHeaderHolder, readWriteLock, cryptor, chunkCache, bufferPool, options, fileSize, lastModified, currentPath, new AtomicReference<>(null), new CiphertextFileKey(), writeGuard, exceptionsDuringWrite, closeListener, ignored -> {}, stats, new StubInUseManager());
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
		long limitConsideringEof = writeGuard.readableSize(ciphertextFileChannel, fileSize.get()) - position;
		if (limitConsideringEof < 1) {
			return -1;
		}
		dst.limit((int) min(origLimit, dst.position() + limitConsideringEof));
		int read = 0;
		boolean reachedEnd = false;
		int payloadSize = cryptor.fileContentCryptor().cleartextChunkSize();
		try {
			while (dst.hasRemaining() && !reachedEnd) {
				long pos = position + read;
				long chunkIndex = pos / payloadSize; // floor by int-truncation
				int offsetInChunk = (int) (pos % payloadSize); // known to fit in int, because payloadSize is int
				try (var chunk = chunkCache.getChunk(chunkIndex)) {
					reachedEnd = offsetInChunk >= chunk.data().limit(); // the ciphertext got shorter while this file was open
					if (!reachedEnd) {
						ByteBuffer data = chunk.data().duplicate().position(offsetInChunk);
						int len = min(dst.remaining(), data.remaining()); // known to fit in int, because second argument is int
						dst.put(data.limit(data.position() + len));
						read += len;
					}
				}
			}
		} finally {
			dst.limit(origLimit);
		}
		stats.addBytesRead(read);
		return reachedEnd && read == 0 ? -1 : read;
	}

	@Override
	protected int writeLocked(ByteBuffer src, long position) throws IOException {
		admitWrite();
		return writeAdmitted(src, position);
	}

	@Override
	protected int writeRelativeLocked(ByteBuffer src) throws IOException {
		if (!options.append()) {
			return super.writeRelativeLocked(src);
		}
		admitWrite();
		long endOfFile = fileSize.get(); // read after admitting and written without writeLocked, whose second admission could adopt a newer size
		int written = writeAdmitted(src, endOfFile);
		position = endOfFile + written;
		return written;
	}

	private void admitWrite() throws IOException {
		var path = currentFilePath.get();
		if (path != null && inUseManager.isInUseByOthers(path)) {
			var useInfo = inUseManager.getUseInfo(path).orElse(new UseInfo("UNKNOWN", Instant.now()));
			var cleartextPath = currentCleartextPath.get();
			if (cleartextPath != null) {
				eventConsumer.accept(new FileIsInUseEvent(cleartextPath, path, useInfo.owner(), useInfo.lastUpdated(), () -> inUseManager.ignoreInUse(path)));
			} else {
				LOG.warn("Unable to emit FileIsInUseEvent: Cleartext path is null. Ciphertext path is {}.", path);
			}
			throw new FileAlreadyInUseException(path);
		}
		admitChange();
	}

	private void admitChange() throws IOException {
		if (writeGuard.beforeWrite(ciphertextFileChannel)) {
			chunkCache.invalidateStale(); // cached chunks may no longer be what is on disk, e.g. a tail that got longer
		}
	}

	private int writeAdmitted(ByteBuffer src, long position) throws IOException {
		long oldFileSize = fileSize.get();
		long written;
		if (position > oldFileSize) {
			writeGuard.beforeGapWrite();
			// we need to fill the gap:
			long gapLen = position - oldFileSize;
			final ByteSource byteSource = ByteSource.repeatingZeroes(gapLen).followedBy(src); // prepend zeros to the original src
			written = writeLockedInternal(byteSource, oldFileSize) - gapLen; // fill the gap by beginning to write from old EOF
		} else {
			final ByteSource byteSource = ByteSource.from(src);
			written = writeLockedInternal(byteSource, position);
		}
		assert written <= src.capacity();
		writeGuard.throwIfConflicted(); // an eviction during this write may have found a conflict
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
				try (var _ = chunkCache.lockForEdit(); Chunk chunk = fullChunkForWrite(chunkIndex, cleartextChunkData)) {
					markEdited(chunkIndex, chunk);
				}
			} else {
				/*
				 * TODO performance:
				 * We don't actually need to read the current data into the cache.
				 * It would suffice if store the written data and do reading when storing the chunk.
				 */
				try (var _ = chunkCache.lockForEdit(); Chunk chunk = chunkForWrite(chunkIndex)) {
					int oldLimit = chunk.data().limit();
					int newLimit = Math.max(oldLimit, offsetInChunk + len);
					ByteBuffer target = chunk.data().duplicate().limit(newLimit); // the chunk's limit grows only once the copy succeeded, so a failed one exposes no pooled bytes
					zero(target, oldLimit, offsetInChunk);
					src.copyTo(target.position(offsetInChunk));
					chunk.data().limit(newLimit);
					markEdited(chunkIndex, chunk);
				}
			}
			written += len;
		}
		long minSize = position + written;
		long newSize = fileSize.updateAndGet(size -> max(minSize, size));
		assert newSize >= minSize;
		if (options.syncData()) {
			forceInternal(options.syncDataAndMetadata());
		}
		stats.addBytesWritten(written);
		return written;
	}

	@Override
	protected long transferFromLocked(ReadableByteChannel src, long position, long count) throws IOException {
		admitChange();
		return super.transferFromLocked(src, position, count);
	}

	private void assertStillOpen() throws AsynchronousCloseException {
		if (!isOpen()) { // nothing would save an edit made after the closing flush
			throw new AsynchronousCloseException();
		}
	}

	private Chunk chunkForWrite(long chunkIndex) throws IOException {
		assertStillOpen();
		return chunkCache.getChunkForWrite(chunkIndex, ciphertextFileChannel);
	}

	private Chunk fullChunkForWrite(long chunkIndex, ByteBuffer cleartextChunkData) throws IOException {
		assertStillOpen();
		return chunkCache.putChunk(chunkIndex, cleartextChunkData, ciphertextFileChannel);
	}

	private void markEdited(long chunkIndex, Chunk chunk) {
		chunk.dirty().set(true);
		writeGuard.markUnsaved(chunkIndex);
		lastModified.set(Instant.now()); // together with the edit, so that another channel's force can't save it and persist an older time
	}

	private static void zero(ByteBuffer data, int from, int to) {
		for (int i = from; i < to; i++) { // a pooled buffer still holds the bytes of whichever file used it last
			data.put(i, (byte) 0);
		}
	}

	private void writeHeaderIfNeeded() throws IOException {
		if (fileHeaderHolder.headerIsPersisted().get()) {
			return;
		}
		LOG.trace("{} - Writing file header.", this);
		ByteBuffer header = fileHeaderHolder.getEncrypted().duplicate().rewind();
		writeGuard.guardedHeaderWrite(ciphertextFileChannel, header, () -> {
			while (header.hasRemaining()) { // a short write must not leave a torn header marked as persisted
				if (ciphertextFileChannel.write(header, header.position()) <= 0) {
					throw new IOException("Unable to make progress while writing file header");
				}
			}
			fileHeaderHolder.headerIsPersisted().set(true);
		});
	}

	@Override
	protected void truncateLocked(long newSize) throws IOException {
		Preconditions.checkArgument(newSize >= 0);
		admitChange();
		if (newSize < fileSize.get()) {
			int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
			long indexOfLastChunk = (newSize + cleartextChunkSize - 1) / cleartextChunkSize - 1;
			int sizeOfIncompleteChunk = (int) (newSize % cleartextChunkSize); // known to fit in int, because cleartextChunkSize is int
			chunkCache.flush(); // a conflict in another chunk must surface while the tail is still intact
			if (sizeOfIncompleteChunk > 0) {
				writeGuard.throwIfConflicted();
				shortenLastChunk(indexOfLastChunk, sizeOfIncompleteChunk);
			}
			long ciphertextFileSize = cryptor.fileHeaderCryptor().headerSize() + cryptor.fileContentCryptor().ciphertextSize(newSize);
			chunkCache.invalidateStale(); // make sure no chunks _after_ newSize exist that would otherwise be written during the next cache eviction
			lastModified.set(Instant.now()); // before the guard makes this change eligible for another channel's force to persist
			writeGuard.guardedTruncate(ciphertextFileSize, ciphertextFileChannel);
			position = min(newSize, position);
			fileSize.set(newSize);
		}
	}

	private void shortenLastChunk(long chunkIndex, int newLimit) throws IOException {
		Chunk chunk;
		int oldLimit;
		try (var _ = chunkCache.lockForEdit()) {
			chunk = chunkForWrite(chunkIndex);
			oldLimit = chunk.data().limit();
			chunk.data().limit(newLimit);
			zero(chunk.data(), oldLimit, newLimit);
			markEdited(chunkIndex, chunk);
		}
		try (chunk) { // held through the save, so that an eviction can't save the short record
			chunkCache.flush(() -> {
				if (chunk.isDirty()) { // not saved: restore the old length, so that a later save writes the whole chunk instead of a short record in front of the old tail
					chunk.data().limit(oldLimit);
				}
			});
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
			writeGuard.throwIfConflicted();
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
		writeGuard.persistOwnTimes(isWritable(), lastModifiedTime -> {
			FileTime lastAccessTime = FileTime.from(Instant.now());
			var p = currentFilePath.get();
			// best effort: setTimes resolves the path again, because NIO can't set times through an open channel. A replacement right after the check goes unnoticed.
			if (p != null && isSameCiphertextFile(p)) {
				p.getFileSystem().provider() //
						.getFileAttributeView(p, BasicFileAttributeView.class) //
						.setTimes(lastModifiedTime, lastAccessTime, null);
			}
		});
	}

	private boolean isSameCiphertextFile(Path p) {
		if (!ciphertextFileKey.isCaptured()) {
			return true;
		}
		try {
			if (ciphertextFileKey.matches(CiphertextFileKey.read(p))) {
				return true;
			}
			LOG.debug("Not persisting last modified time, ciphertext file {} was replaced.", p);
		} catch (IOException e) {
			LOG.debug("Not persisting last modified time, failed to read file key of {}.", p, e);
		}
		return false;
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
		var range = ciphertextRangeOfChunks(pos, size);
		FileLock ciphertextLock = ciphertextFileChannel.lock(range.position(), range.size(), shared);
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
		var range = ciphertextRangeOfChunks(pos, size);
		FileLock ciphertextLock = ciphertextFileChannel.tryLock(range.position(), range.size(), shared);
		if (ciphertextLock == null) {
			return null;
		} else {
			return new CleartextFileLock(this, ciphertextLock, pos, size);
		}
	}

	private record CiphertextRange(long position, long size) {}

	private CiphertextRange ciphertextRangeOfChunks(long cleartextPos, long cleartextSize) {
		long beginOfFirstChunk = beginOfChunk(cleartextPos);
		long beginOfLastChunk = beginOfChunk(cleartextPos + cleartextSize);
		if (beginOfFirstChunk == Long.MAX_VALUE || beginOfLastChunk == Long.MAX_VALUE) {
			long headerSize = cryptor.fileHeaderCryptor().headerSize();
			return new CiphertextRange(headerSize, Long.MAX_VALUE - headerSize); // leaves the header readable, as joining channels verify it and Windows denies reads in a range locked by another handle
		} else {
			long endOfLastChunk = beginOfLastChunk + cryptor.fileContentCryptor().ciphertextChunkSize();
			return new CiphertextRange(beginOfFirstChunk, endOfLastChunk - beginOfFirstChunk);
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
				() -> closeListener.accept(ciphertextFileChannel), //
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
