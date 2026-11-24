package org.cryptomator.cryptofs.fh;

import jakarta.inject.Inject;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
import org.cryptomator.cryptofs.common.RunnableThrowingException;
import org.cryptomator.cryptofs.inuse.InUseManager;
import org.cryptomator.cryptofs.inuse.UseToken;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

@OpenFileScoped
public class OpenCryptoFile implements Closeable {

	private static final Logger LOG = LoggerFactory.getLogger(OpenCryptoFile.class);

	private final FileCloseListener listener;
	private final AtomicReference<Instant> lastModified;
	private final InUseManager inUseManager;
	private final Cryptor cryptor;
	private final FileHeaderHolder headerHolder;
	private final ChunkIO chunkIO;
	private final CiphertextFileKey ciphertextFileKey;
	private final CiphertextWriteGuard writeGuard;
	private final AtomicReference<Path> currentFilePath;
	private final AtomicReference<CryptoPath> currentCleartextPath;
	private final AtomicLong fileSize;
	private final OpenCryptoFileComponent component;

	private final AtomicInteger openChannelsCount = new AtomicInteger(0);
	private volatile UseToken useToken;
	private Path detachedPath; // guarded by this; non-null once an open detached this file, so later opens retry instead of failing like after a delete
	private boolean retired; // guarded by this; true once closed, so opens that got this file before it was unregistered retry with a fresh one

	@Inject
	public OpenCryptoFile(FileCloseListener listener, Cryptor cryptor, FileHeaderHolder headerHolder, ChunkIO chunkIO, CiphertextFileKey ciphertextFileKey, CiphertextWriteGuard writeGuard, //
						  @CurrentOpenFilePath AtomicReference<Path> currentFilePath, @OpenFileSize AtomicLong fileSize, //
						  @CurrentOpenFileCleartextPath AtomicReference<CryptoPath> currentCleartextPath, //
						  @OpenFileModifiedDate AtomicReference<Instant> lastModified, OpenCryptoFileComponent component, //
						  InUseManager inUseManager) {
		this(listener, cryptor, headerHolder, chunkIO, ciphertextFileKey, writeGuard, currentFilePath, fileSize, currentCleartextPath, lastModified, component, inUseManager, UseToken.CLOSED_TOKEN);
	}

	//for testing
	OpenCryptoFile(FileCloseListener listener, Cryptor cryptor, FileHeaderHolder headerHolder, ChunkIO chunkIO, CiphertextFileKey ciphertextFileKey, CiphertextWriteGuard writeGuard, //
				   @CurrentOpenFilePath AtomicReference<Path> currentFilePath, @OpenFileSize AtomicLong fileSize, //
				   @CurrentOpenFileCleartextPath AtomicReference<CryptoPath> currentCleartextPath, //
				   @OpenFileModifiedDate AtomicReference<Instant> lastModified, OpenCryptoFileComponent component, //
				   InUseManager inUseManager, UseToken token) {
		this.listener = listener;
		this.cryptor = cryptor;
		this.headerHolder = headerHolder;
		this.chunkIO = chunkIO;
		this.ciphertextFileKey = ciphertextFileKey;
		this.writeGuard = writeGuard;
		this.currentFilePath = currentFilePath;
		this.currentCleartextPath = currentCleartextPath;
		this.fileSize = fileSize;
		this.component = component;
		this.lastModified = lastModified;
		this.inUseManager = inUseManager;
		this.useToken = token;
	}

	/**
	 * Creates a new file channel with the given open options.
	 *
	 * @param options The options to use to open the file channel. For the most part these will be passed through to the ciphertext channel. {@link java.nio.file.StandardOpenOption#TRUNCATE_EXISTING} is left to the caller, see {@link OpenCryptoFiles.OpenOperation#newFileChannel(org.cryptomator.cryptofs.CryptoPath, EffectiveOpenOptions, FileAttribute[])}.
	 * @return A new file channel. Ideally used in a try-with-resource statement. If the channel is not properly closed, this OpenCryptoFile will stay open indefinite.
	 * @throws IOException Also a {@link CiphertextReplacedException} if the ciphertext file at the path is no longer, or can't be confirmed to be, the one of this open file, or if this open file stopped saving because its ciphertext changed in place. In that case this open file has been detached like a deleted file.
	 * An {@link OpenFileRetiredException} if this open file has been closed.
	 */
	public synchronized FileChannel newFileChannel(EffectiveOpenOptions options, FileAttribute<?>... attrs) throws IOException {
		Path path = pathToOpen();
		FileChannel ciphertextFileChannel = null;
		CleartextFileChannel cleartextFileChannel = null;
		boolean unlinkedByOpen = false;

		boolean joining = openChannelsCount.incrementAndGet() > 1; // synchronized context, hence we can proactively increase the number
		try {
			if (joining && writeGuard.isConflicted()) {
				throw detachAsReplaced(path, true); // a new open starts on the current ciphertext, and this file's channels can no longer save over it
			}
			Instant lastModifiedBeforeOpen = lastModified.get();
			boolean readFileKey = !joining || ciphertextFileKey.isCaptured();
			captureOrMatchFileKeyBeforeOpen(path, joining, readFileKey);
			if (options.writable() && useToken.isClosed()) { //the token was closed prematurely, so we try to get a new one
				useToken = inUseManager.use(path);
			}
			ciphertextFileChannel = path.getFileSystem().provider().newFileChannel(path, options.createOpenOptionsForEncryptedFile(), attrs);
			BasicFileAttributes attrsAfterOpen = null;
			if (readFileKey || options.deleteOnClose()) {
				try {
					attrsAfterOpen = CiphertextFileKey.readAttributes(path);
				} catch (NoSuchFileException _) {
					unlinkedByOpen = options.deleteOnClose(); // the JDK unlinks such files while opening them, except on Windows
				} catch (IOException e) {
					LOG.debug("Failed to read file key of {}.", path, e);
				}
			}
			checkSameCiphertextAfterOpen(path, options, joining, attrsAfterOpen, unlinkedByOpen, ciphertextFileChannel);
			initFileHeader(options, ciphertextFileChannel);
			if (!joining) {
				adoptAttributes(attrsAfterOpen, lastModifiedBeforeOpen);
			}
			initFileSize(ciphertextFileChannel);
			cleartextFileChannel = component.newChannelComponent() //
					.create(ciphertextFileChannel, options, this::cleartextChannelClosed) //
					.channel();
		} finally {
			if (cleartextFileChannel == null) { // i.e. something didn't work
				cleartextChannelClosed(ciphertextFileChannel);
				closeQuietly(ciphertextFileChannel);
			}
		}
		assert cleartextFileChannel != null; // otherwise there would have been an exception
		chunkIO.registerChannel(ciphertextFileChannel, options.writable());
		if (unlinkedByOpen) {
			detach(path);
		}
		return cleartextFileChannel;
	}

	private Path pathToOpen() throws IOException {
		Path path = currentFilePath.get();
		if (path == null && detachedPath != null) {
			throw new CiphertextReplacedException(detachedPath, true);
		} else if (path == null) {
			throw new IllegalStateException("Cannot create file channel to deleted file");
		} else if (retired) {
			throw new OpenFileRetiredException(path);
		}
		return path;
	}

	private void captureOrMatchFileKeyBeforeOpen(Path path, boolean joining, boolean readFileKey) throws CiphertextReplacedException {
		Object keyBeforeOpen = readFileKey ? readFileKeyOrNull(path) : null;
		if (!joining) {
			ciphertextFileKey.capture(keyBeforeOpen); // compared with the key read after opening, to notice a replacement during the open
		} else if (!ciphertextFileKey.matches(keyBeforeOpen)) {
			throw detachAsReplaced(path, true); // an open with DELETE_ON_CLOSE would unlink the replacement
		}
	}

	private void checkSameCiphertextAfterOpen(Path path, EffectiveOpenOptions options, boolean joining, BasicFileAttributes attrsAfterOpen, boolean unlinkedByOpen, FileChannel ciphertextFileChannel) throws IOException {
		Object keyAfterOpen = attrsAfterOpen != null ? attrsAfterOpen.fileKey() : null;
		// a joining channel needs evidence of a replacement, as detaching leaves the other channels on an open file whose ciphertext a fresh one may then open too
		boolean sameCiphertext = joining //
				? verifySameCiphertext(keyAfterOpen, ciphertextFileChannel) //
				: isOpenedFileAtPath(attrsAfterOpen, unlinkedByOpen, ciphertextFileChannel);
		if (!sameCiphertext) {
			throw detachAsReplaced(path, !options.deleteOnClose()); // reopening might unlink another file
		}
	}

	private boolean isOpenedFileAtPath(BasicFileAttributes attrsAfterOpen, boolean unlinkedByOpen, FileChannel ciphertextFileChannel) throws IOException {
		if (attrsAfterOpen == null) {
			return !ciphertextFileKey.isCaptured() || unlinkedByOpen; // a captured key needs the attributes to be confirmed, unless this open unlinked the file
		} else if (attrsAfterOpen.fileKey() == null || ciphertextFileKey.isCaptured()) {
			return ciphertextFileKey.matches(attrsAfterOpen.fileKey());
		} else {
			// Without a file key captured before opening, e.g. for a file this open created, nothing ties the key read from the path to the opened file.
			// A size that differs from the channel's shows that another file got there in between.
			return attrsAfterOpen.size() == ciphertextFileChannel.size();
		}
	}

	private void adoptAttributes(BasicFileAttributes attrsAfterOpen, Instant lastModifiedBeforeOpen) {
		if (attrsAfterOpen != null) {
			ciphertextFileKey.capture(attrsAfterOpen.fileKey());
			// The file may have been replaced since this open file got created. A time set while this open ran, e.g. via an attribute view, wins.
			lastModified.compareAndSet(lastModifiedBeforeOpen, attrsAfterOpen.lastModifiedTime().toInstant());
		}
	}

	/**
	 * Checks whether the given ciphertext channel, just opened to join this open file, is opened on the same file as the other channels.
	 *
	 * @param fileKey The file key read from the path after opening the channel, or <code>null</code> if unknown
	 * @param candidate The ciphertext channel to check
	 * @return <code>false</code> if the file key or the file header shows that the file at the path is another file
	 * @throws IOException If reading the file header fails
	 */
	//visible for testing
	boolean verifySameCiphertext(Object fileKey, FileChannel candidate) throws IOException {
		return ciphertextFileKey.matches(fileKey) && headerHolder.isHeaderOf(candidate);
	}

	private static Object readFileKeyOrNull(Path path) {
		try {
			return CiphertextFileKey.read(path);
		} catch (IOException _) {
			return null;
		}
	}

	private CiphertextReplacedException detachAsReplaced(Path path, boolean retryable) {
		detach(path);
		return new CiphertextReplacedException(path, retryable);
	}

	// detaches like a deleted file, so that concurrent and later openers retry with a fresh OpenCryptoFile for the file now at the path
	private void detach(Path path) {
		detachedPath = path;
		updateCurrentFilePath(null);
		listener.close(path, this);
	}

	//visible for testing
	void initFileHeader(EffectiveOpenOptions options, FileChannel ciphertextFileChannel) throws IOException {
		try {
			headerHolder.get();
		} catch (IllegalStateException e) {
			//first file channel to file
			if (options.createNew() || (options.create() && ciphertextFileChannel.size() == 0)) {
				//file did not exist, create new header
				//file size will never be zero again, once the header is written because we retain on truncation the header
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
		if (fileSize.get() == -1L) {
			LOG.trace("First channel for this openFile. Initializing file size...");
			long cleartextSize = 0L;
			try {
				long ciphertextSize = ciphertextFileChannel.size();
				writeGuard.seedSize(ciphertextSize);
				if (ciphertextSize > 0L) {
					long payloadSize = ciphertextSize - cryptor.fileHeaderCryptor().headerSize();
					cleartextSize = cryptor.fileContentCryptor().cleartextSize(payloadSize);
				}
			} catch (IllegalArgumentException e) {
				LOG.warn("Invalid cipher text file size. Assuming empty file.", e);
			}
			fileSize.compareAndSet(-1L, cleartextSize);
		}
	}

	/**
	 * @return The size of the opened file. Note that the filesize is unknown until a {@link #newFileChannel(EffectiveOpenOptions, FileAttribute[])} is opened. In this case this method returns an empty optional.
	 */
	public Optional<Long> size() {
		long val = fileSize.get();
		if (val == -1L) {
			return Optional.empty();
		} else {
			return Optional.of(val);
		}
	}

	public FileTime getLastModifiedTime() {
		return FileTime.from(lastModified.get());
	}

	/**
	 * Writes times set through an attribute view, so that no save of this file takes them for a change by someone else.
	 * A modification time written to this file's current ciphertext path also becomes this file's own.
	 *
	 * @param ciphertextPath The ciphertext file the write goes to
	 * @param lastModifiedTime The modification time the write sets, or <code>null</code>
	 */
	public void writeTimes(Path ciphertextPath, FileTime lastModifiedTime, RunnableThrowingException<IOException> write) throws IOException {
		writeGuard.persistViewTimes(ciphertextPath, lastModifiedTime, write);
	}

	/**
	 * @param fileKey A file key read from the ciphertext path of this open file, or <code>null</code> if the file system has none
	 * @return <code>false</code> if the file key shows that the ciphertext file at the path is another file than this open file's
	 */
	public boolean matchesFileKey(Object fileKey) {
		return ciphertextFileKey.matches(fileKey);
	}

	public Path getCurrentFilePath() {
		return currentFilePath.get();
	}

	public CryptoPath getCurrentCleartextPath() {
		return currentCleartextPath.get();
	}

	/**
	 * Updates the current ciphertext file path, if it is not already set to null (i.e., the openCryptoFile is deleted)
	 *
	 * @param newFilePath new ciphertext path
	 */
	public void updateCurrentFilePath(Path newFilePath) {
		if (newFilePath == null) {
			writeGuard.rememberPaths();
		}
		currentFilePath.getAndUpdate(p -> p == null ? null : newFilePath);
		if (newFilePath != null) {
			useToken.moveTo(newFilePath);
		} else {
			currentCleartextPath.set(null);
			useToken.close(); //encrypted file will be deleted, hence we can stop checking usage
		}
	}

	/**
	 * Updates the cleartext path if the file is not deleted (i.e., currentFilePath is not null).
	 * Null input is ignored.
	 *
	 * @param cleartextPath new cleartext path, or null to skip update
	 */
	public void updateCurrentCleartextPath(CryptoPath cleartextPath) {
		if (cleartextPath == null) {
			return;
		}
		currentCleartextPath.getAndUpdate(p -> currentFilePath.get() == null ? p : cleartextPath);
	}

	// a move remaps the file while holding this monitor, so the last channel unregisters it either before or after the remap
	private synchronized void cleartextChannelClosed(FileChannel ciphertextFileChannel) {
		if (ciphertextFileChannel != null) {
			chunkIO.unregisterChannel(ciphertextFileChannel);
		}
		if (openChannelsCount.decrementAndGet() == 0) {
			close();
		}
	}

	@Override
	public synchronized void close() {
		retired = true;
		var p = currentFilePath.get();
		if (p != null) {
			useToken.close();
			listener.close(p, this);
		}
	}

	@Override
	public String toString() {
		return "OpenCryptoFile(path=" + currentFilePath.toString() + ")";
	}
}
