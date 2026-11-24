package org.cryptomator.cryptofs.fh;

import jakarta.inject.Inject;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.common.RunnableThrowingException;
import org.cryptomator.cryptofs.event.FileWriteConflictEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/**
 * Keeps an open file from saving over ciphertext that changed in place outside of this file system.
 * <p>
 * Such a change keeps the file key, so before each save this guard compares the ciphertext with what this open file last read or wrote.
 * On a mismatch it refuses the save, stops all further saves through this open file and emits one {@link FileWriteConflictEvent}.
 * <p>
 * Its lock is the innermost one: the open file's read-write lock, the chunk cache lock, Caffeine compute, then this lock.
 * It is held across the guarded I/O, so that check and write stay together. It is never held across an event consumer or code that takes another lock.
 * Reads don't take it, because that I/O can be a network round trip.
 */
@OpenFileScoped
public class CiphertextWriteGuard {

	private static final Logger LOG = LoggerFactory.getLogger(CiphertextWriteGuard.class);
	private static final int EDGE_SIZE = 16;
	private static final Fingerprint ABSENT = new Fingerprint(0, ByteBuffer.allocate(0), ByteBuffer.allocate(0));

	private final Cryptor cryptor;
	private final ChunkIO ciphertext;
	private final FileHeaderHolder headerHolder;
	private final AtomicLong fileSize;
	private final AtomicReference<Instant> lastModified;
	private final Consumer<FilesystemEvent> eventConsumer;
	private final AtomicReference<Path> currentPath;
	private final AtomicReference<CryptoPath> currentCleartextPath;

	private final ReentrantLock lock = new ReentrantLock();
	private final Map<Long, Fingerprint> baselines = new ConcurrentHashMap<>();
	private final Set<Long> unsaved = ConcurrentHashMap.newKeySet();
	private final AtomicBoolean conflicted = new AtomicBoolean();
	private final AtomicReference<Path> lastKnownPath = new AtomicReference<>();
	private final AtomicReference<String> lastKnownCleartextPath = new AtomicReference<>();
	private volatile long expectedSize; // written under lock
	private boolean adoptedForeignShrink; // guarded by lock
	private boolean ownChanges; // guarded by lock
	private boolean savedOnce; // guarded by lock
	private boolean ownTimeWithheld; // guarded by lock
	private boolean timeReadAtClose; // guarded by lock
	private FileTime timeBaseline; // guarded by lock
	private boolean foreignTimeChange; // guarded by lock

	@Inject
	public CiphertextWriteGuard(Cryptor cryptor, ChunkIO ciphertext, FileHeaderHolder headerHolder, @OpenFileSize AtomicLong fileSize, @OpenFileModifiedDate AtomicReference<Instant> lastModified, Consumer<FilesystemEvent> eventConsumer, //
								@CurrentOpenFilePath AtomicReference<Path> currentPath, @CurrentOpenFileCleartextPath AtomicReference<CryptoPath> currentCleartextPath) {
		this.cryptor = cryptor;
		this.ciphertext = ciphertext;
		this.headerHolder = headerHolder;
		this.fileSize = fileSize;
		this.lastModified = lastModified;
		this.eventConsumer = eventConsumer;
		this.currentPath = currentPath;
		this.currentCleartextPath = currentCleartextPath;
	}

	/**
	 * Writes a chunk's ciphertext through the channel the guard selected for its checks.
	 */
	@FunctionalInterface
	public interface ChunkWrite {

		void writeTo(FileChannel channel) throws IOException;
	}

	/**
	 * Writes the times of the ciphertext file.
	 */
	@FunctionalInterface
	public interface TimesWrite {

		/**
		 * @param lastModifiedTime The modification time to write, or <code>null</code> to keep the one on disk
		 */
		void write(FileTime lastModifiedTime) throws IOException;
	}

	/**
	 * The length and outer bytes of a chunk's ciphertext. A completed rewrite always changes the first bytes.
	 */
	private record Fingerprint(int length, ByteBuffer head, ByteBuffer tail) {

		static Fingerprint of(ByteBuffer ciphertext) {
			int length = ciphertext.remaining();
			int edge = Math.min(EDGE_SIZE, length);
			return new Fingerprint(length, copy(ciphertext, ciphertext.position(), edge), copy(ciphertext, ciphertext.limit() - edge, edge));
		}

		private static ByteBuffer copy(ByteBuffer source, int index, int length) {
			byte[] bytes = new byte[length];
			source.get(index, bytes);
			return ByteBuffer.wrap(bytes);
		}
	}

	boolean isConflicted() {
		return conflicted.get();
	}

	public void throwIfConflicted() throws IOException {
		if (isConflicted()) {
			throw refusal();
		}
	}

	/**
	 * @param ciphertextSize The raw size at the first open. An invalid one is tolerated, as it predates this open file.
	 */
	void seedSize(long ciphertextSize) {
		lock.lock();
		try {
			expectedSize = ciphertextSize;
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Admits a write or truncate. A valid changed size is adopted if nothing unsaved depends on the old one, otherwise the write is refused as a conflict.
	 *
	 * @param own The ciphertext channel of the channel that is writing
	 * @return <code>true</code> if a size changed outside of this file system was adopted, so that cached chunks may be stale
	 * @throws IOException If the file is conflicted or this check finds a conflict
	 */
	public boolean beforeWrite(FileChannel own) throws IOException {
		lock.lock();
		try {
			throwIfConflicted();
			long actual = own.size();
			if (timeBaseline == null) {
				timeBaseline = readTimeOrNull(); // sampled here, as a foreign touch between open and first write must not suppress that write's own time
			}
			if (actual == expectedSize) {
				return false;
			}
			long cleartextSize = validCleartextSize(actual);
			if (!unsaved.isEmpty() || cleartextSize < 0) {
				throw conflict();
			}
			adoptedForeignShrink |= actual < expectedSize;
			expectedSize = actual;
			fileSize.set(cleartextSize);
			return true;
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Refuses a write that would fill a gap past the end, once the file got shorter outside of this file system.
	 * Such a write would otherwise authenticate zeros over the range that was removed.
	 *
	 * @throws IOException If the file got shorter outside of this file system while it was open
	 */
	public void beforeGapWrite() throws IOException {
		lock.lock(); // so that a save already admitted finishes before the conflicted flag lets a new open read the file
		try {
			if (adoptedForeignShrink) {
				throw conflict();
			}
		} finally {
			lock.unlock();
		}
	}

	private long validCleartextSize(long ciphertextSize) {
		if (ciphertextSize == 0) {
			return 0;
		}
		try {
			return cryptor.fileContentCryptor().cleartextSize(ciphertextSize - cryptor.fileHeaderCryptor().headerSize());
		} catch (IllegalArgumentException _) {
			return -1;
		}
	}

	/**
	 * Determines how far a read may reach, never past the logical size. That is what is on disk, or as far as this file's unsaved chunks reach.
	 * Unsaved chunks count only while the file is not conflicted and the disk has not fallen below this file's last save.
	 *
	 * @param own The ciphertext channel of the channel that is reading
	 * @param logicalSize The cleartext size of the open file
	 * @throws IOException If the ciphertext size cannot be read
	 */
	public long readableSize(FileChannel own, long logicalSize) throws IOException {
		int ciphertextChunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
		// read in the reverse order of a save, which writes its bytes, then clears its unsaved mark, then raises the expected size
		long expected = expectedSize;
		long unsavedEnd = isConflicted() ? 0 : unsaved.stream().mapToLong(index -> (index + 1) * cleartextChunkSize).max().orElse(0);
		long actual = own.size();
		if (actual < expected) { // truncates exclude reads, so only a foreign change can shrink the file below the last save
			unsavedEnd = 0;
		}
		long payloadSize = actual - cryptor.fileHeaderCryptor().headerSize();
		long onDisk = 0;
		if (payloadSize > 0) {
			long lastPayload = Math.max(0, payloadSize % ciphertextChunkSize - (ciphertextChunkSize - cleartextChunkSize));
			onDisk = payloadSize / ciphertextChunkSize * cleartextChunkSize + lastPayload;
		}
		return Math.min(logicalSize, Math.max(onDisk, unsavedEnd));
	}

	void checkHeader(FileChannel own) throws IOException {
		lock.lock();
		try {
			throwIfConflicted();
			if (!headerHolder.isHeaderOf(own)) {
				throw conflict();
			}
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Marks a chunk as holding unsaved data. Only to be called once its edit happened.
	 */
	public void markUnsaved(long chunkIndex) {
		unsaved.add(chunkIndex);
	}

	/**
	 * Records the ciphertext a chunk was loaded from.
	 *
	 * @param loadedCiphertext The bytes read from disk, without any remaining if there were none
	 */
	void observe(long chunkIndex, ByteBuffer loadedCiphertext) {
		baselines.put(chunkIndex, loadedCiphertext.hasRemaining() ? Fingerprint.of(loadedCiphertext) : ABSENT);
	}

	/**
	 * Records what is on disk now for a chunk that is about to be overwritten without being loaded.
	 */
	void captureCurrent(long chunkIndex, FileChannel own) throws IOException {
		lock.lock();
		try {
			long position = chunkPosition(chunkIndex);
			long length = Math.min(cryptor.fileContentCryptor().ciphertextChunkSize(), own.size() - position);
			if (length <= 0) {
				baselines.put(chunkIndex, ABSENT);
			} else {
				int edge = (int) Math.min(EDGE_SIZE, length);
				baselines.put(chunkIndex, new Fingerprint((int) length, read(own, position, edge), read(own, position + length - edge, edge)));
			}
		} finally {
			lock.unlock();
		}
	}

	/**
	 * @return Whether a clean cached chunk still is what is on disk, including its length
	 */
	boolean isCurrent(long chunkIndex, FileChannel own) throws IOException {
		lock.lock();
		try {
			return matches(own, chunkIndex, baselines.get(chunkIndex), true);
		} finally {
			lock.unlock();
		}
	}

	void forget(long chunkIndex) {
		baselines.remove(chunkIndex);
		unsaved.remove(chunkIndex);
	}

	/**
	 * Saves a chunk, if the ciphertext is still what this open file last saw.
	 * <p>
	 * After a failed write, the bytes it completed are known from the buffer's position. They are recorded, so that a retry succeeds and still detects a foreign change.
	 *
	 * @param position Position of the chunk in the ciphertext file
	 * @param ciphertextChunk The encrypted chunk, whose position the write advances
	 * @param write The write to run with the selected channel
	 * @throws IOException If the save was refused or failed
	 */
	void guardedSave(long chunkIndex, long position, ByteBuffer ciphertextChunk, ChunkWrite write) throws IOException {
		lock.lock();
		try {
			throwIfConflicted();
			FileChannel channel = ciphertext.getWritableChannel();
			Fingerprint before = baselines.get(chunkIndex);
			checkUnchanged(channel);
			if (!matches(channel, chunkIndex, before, false)) { // length unchecked, as a later chunk of this file can legitimately extend a former partial tail; checkUnchanged compared the raw size
				throw conflict();
			}
			ByteBuffer attempted = ciphertextChunk.duplicate();
			try {
				write.writeTo(channel);
			} catch (IOException | RuntimeException e) {
				int completed = ciphertextChunk.position() - attempted.position();
				if (completed > 0) {
					baselines.put(chunkIndex, afterPartialWrite(before, attempted, completed));
					recordOwnChange(Math.max(expectedSize, position + completed));
				}
				throw e;
			}
			baselines.put(chunkIndex, Fingerprint.of(attempted));
			unsaved.remove(chunkIndex);
			recordOwnChange(Math.max(expectedSize, position + attempted.remaining()));
		} finally {
			lock.unlock();
		}
	}

	private static Fingerprint afterPartialWrite(Fingerprint before, ByteBuffer attempted, int completed) {
		Fingerprint old = before == null ? ABSENT : before;
		int length = Math.max(old.length(), completed);
		int edge = Math.min(EDGE_SIZE, length);
		byte[] head = new byte[edge];
		byte[] tail = new byte[edge];
		for (int i = 0; i < edge; i++) {
			head[i] = byteAfterPartialWrite(old, attempted, completed, i);
			tail[i] = byteAfterPartialWrite(old, attempted, completed, length - edge + i);
		}
		return new Fingerprint(length, ByteBuffer.wrap(head), ByteBuffer.wrap(tail));
	}

	private static byte byteAfterPartialWrite(Fingerprint old, ByteBuffer attempted, int completed, int offset) {
		if (offset < completed) {
			return attempted.get(attempted.position() + offset);
		} else if (offset < old.head().remaining()) {
			return old.head().get(offset);
		}
		return old.tail().get(offset - (old.length() - old.tail().remaining()));
	}

	/**
	 * Writes the file header, if the ciphertext is still what this open file last saw.
	 *
	 * @param header The header, whose position the write advances
	 * @throws IOException If the write was refused or failed
	 */
	public void guardedHeaderWrite(FileChannel channel, ByteBuffer header, RunnableThrowingException<IOException> write) throws IOException {
		lock.lock();
		try {
			throwIfConflicted();
			checkUnchanged(channel);
			try {
				write.run();
			} catch (IOException | RuntimeException e) {
				if (header.position() > 0) {
					recordOwnChange(Math.max(expectedSize, header.position()));
				}
				throw e;
			}
			recordOwnChange(Math.max(expectedSize, cryptor.fileHeaderCryptor().headerSize()));
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Truncates the ciphertext, if it is still what this open file last saw.
	 *
	 * @param ciphertextSize The new raw size
	 * @throws IOException If the truncation was refused or failed
	 */
	public void guardedTruncate(long ciphertextSize, FileChannel channel) throws IOException {
		lock.lock();
		try {
			throwIfConflicted();
			checkUnchanged(channel);
			channel.truncate(ciphertextSize);
			recordOwnChange(Math.min(ciphertextSize, expectedSize)); // a truncate past the end changes nothing
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Closes a ciphertext channel of this file. Windows may complete the time of a written file only when its handle closes.
	 * Once this file saved, a modification time the file system sets during the close is therefore this file's own, so this file's time gets persisted again.
	 * That doesn't happen after a foreign time change before the close or a close that fails.
	 * It also doesn't happen while an earlier persist withheld this file's time, until a later save or a time set through the view.
	 *
	 * @param close Closes the channel, under this guard's lock
	 * @throws IOException If closing fails
	 */
	public void guardedClose(RunnableThrowingException<IOException> close) throws IOException {
		lock.lock();
		try {
			if (!savedOnce || timeBaseline == null || foreignTimeChange || isConflicted()) {
				close.run();
				return;
			}
			try {
				noteForeignTimeChange();
			} finally {
				close.run();
			}
			if (!foreignTimeChange) {
				var timeAfterClose = readTimeOrNull();
				if (timeAfterClose != null && !timeAfterClose.equals(timeBaseline)) {
					if (!ownTimeWithheld) {
						ownChanges = true;
					}
					timeBaseline = timeAfterClose; // even a withheld time's close is no foreign change
				}
				timeReadAtClose = timeAfterClose != null;
			}
		} finally {
			lock.unlock();
		}
	}

	private void checkUnchanged(FileChannel channel) throws IOException {
		noteForeignTimeChange();
		if (!headerHolder.isHeaderOf(channel) || channel.size() != expectedSize) {
			throw conflict();
		}
	}

	private void recordOwnChange(long newExpectedSize) {
		expectedSize = newExpectedSize;
		ownChanges = true;
		savedOnce = true;
		ownTimeWithheld = false;
		timeBaseline = readTimeOrNull();
		timeReadAtClose = false;
	}

	private void noteForeignTimeChange() {
		if (!foreignTimeChange && timeBaseline != null && !timeBaseline.equals(readTimeOrNull())) { // once set, skips the stat, a round trip on a network share
			foreignTimeChange = true;
		}
	}

	/**
	 * Writes the times of the ciphertext file, including this file's own modification time only where it replaces a time this file left.
	 * Holding the lock keeps a save from landing between reading and writing the times.
	 *
	 * @param mayWriteModifiedTime Whether the caller may write a modification time at all
	 * @param write The write, given this file's own modification time or <code>null</code>
	 * @throws IOException If the times cannot be written, which leaves pending own changes pending
	 */
	public void persistOwnTimes(boolean mayWriteModifiedTime, TimesWrite write) throws IOException {
		lock.lock();
		try {
			boolean ownTime = mayWriteModifiedTime && ownChanges && !isConflicted() && !foreignTimeChange && timeBaseline != null && (timeReadAtClose || timeBaseline.equals(readTimeOrNull())); // a close just read the time
			timeReadAtClose = false;
			write.write(ownTime ? FileTime.from(lastModified.get()) : null);
			if (mayWriteModifiedTime) {
				if (ownChanges) { // a persist with nothing pending, e.g. by another channel, decides nothing about the last save's time
					ownTimeWithheld = !ownTime; // outlives the foreign time change cleared below, so that a close doesn't restore the withheld time
				}
				ownChanges = false;
				foreignTimeChange = false;
			}
			if (ownTime) {
				timeBaseline = readTimeOrNull();
			}
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Writes times set through an attribute view. A modification time written to this file's current ciphertext path becomes this file's own and doesn't count as a foreign change.
	 *
	 * @param target The ciphertext file the write goes to, resolved before calling this, as resolving may take other locks
	 * @param lastModifiedTime The modification time the write sets, or <code>null</code>, which leaves the time baseline as it is
	 */
	void persistViewTimes(Path target, FileTime lastModifiedTime, RunnableThrowingException<IOException> write) throws IOException {
		lock.lock();
		try {
			boolean ownFile = OpenCryptoFiles.normalize(target).equals(currentPath.get()); // before the write, as a move of this file can complete during it
			write.run();
			if (lastModifiedTime != null && ownFile) {
				lastModified.set(lastModifiedTime.toInstant());
				timeBaseline = readTimeOrNull();
				foreignTimeChange = false;
				ownTimeWithheld = false;
			}
		} finally {
			lock.unlock();
		}
	}

	private FileTime readTimeOrNull() {
		Path path = currentPath.get();
		if (path == null) {
			return null;
		}
		try {
			return Files.getLastModifiedTime(path);
		} catch (IOException _) {
			return null;
		}
	}

	/**
	 * To be called before a detach clears the current paths, so that later events can still name the file.
	 */
	void rememberPaths() {
		Path path = currentPath.get();
		if (path != null) {
			CryptoPath cleartextPath = currentCleartextPath.get();
			lastKnownCleartextPath.set(cleartextPath == null ? null : cleartextPath.toString());
			lastKnownPath.set(path);
		}
	}

	/**
	 * @return The file's current ciphertext path, or the last one it had if it was detached
	 */
	Path ciphertextPath() {
		Path current = currentPath.get();
		return current != null ? current : lastKnownPath.get();
	}

	private IOException conflict() {
		if (conflicted.compareAndSet(false, true)) {
			CryptoPath cleartextPath = currentCleartextPath.get();
			var event = new FileWriteConflictEvent(cleartextPath != null ? cleartextPath.toString() : lastKnownCleartextPath.get(), ciphertextPath());
			LOG.warn("Refusing to save {}, its ciphertext changed outside of this file system while the file was open.", event.ciphertextPath());
			Thread.ofVirtual().name("cryptofs-conflict-event").start(() -> eventConsumer.accept(event)); // the detecting thread may hold locks of this or another file
		}
		return refusal();
	}

	private IOException refusal() {
		return new FileSystemException(ciphertextPath().toString(), null, "Ciphertext changed outside of this file system while the file was open");
	}

	private long chunkPosition(long chunkIndex) {
		return chunkIndex * cryptor.fileContentCryptor().ciphertextChunkSize() + cryptor.fileHeaderCryptor().headerSize();
	}

	private boolean matches(FileChannel channel, long chunkIndex, Fingerprint baseline, boolean compareLength) throws IOException {
		if (baseline == null) {
			return true;
		}
		long position = chunkPosition(chunkIndex);
		int chunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		if (baseline == ABSENT) { // nothing there, or a hole left by a later chunk of this file
			return isAllZero(read(channel, position, EDGE_SIZE)) && isAllZero(read(channel, position + chunkSize - EDGE_SIZE, EDGE_SIZE));
		}
		if (compareLength && Math.min(chunkSize, channel.size() - position) != baseline.length()) {
			return false;
		}
		int edge = baseline.head().remaining();
		return read(channel, position, edge).equals(baseline.head()) && read(channel, position + baseline.length() - edge, edge).equals(baseline.tail());
	}

	private static boolean isAllZero(ByteBuffer bytes) {
		return bytes.equals(ByteBuffer.allocate(bytes.remaining()));
	}

	private static ByteBuffer read(FileChannel channel, long position, int length) throws IOException {
		ByteBuffer buffer = ByteBuffer.allocate(length);
		while (buffer.hasRemaining() && channel.read(buffer, position + buffer.position()) > 0) {
			// a single read may return fewer bytes
		}
		return buffer.flip();
	}
}
