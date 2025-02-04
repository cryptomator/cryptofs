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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

@OpenFileScoped
public class OpenCryptoFile implements Closeable {

	private static final Logger LOG = LoggerFactory.getLogger(OpenCryptoFile.class);

	private final FileCloseListener listener;
	private final AtomicReference<Instant> lastModified;
	private final Cryptor cryptor;
	private final FileHeaderHolder headerHolder;
	private final ChunkIO chunkIO;
	private final AtomicReference<ClearAndCipherPath> currentFilePaths;
	private final AtomicLong fileSize;
	private final OpenCryptoFileComponent component;

	private final AtomicInteger openChannelsCount = new AtomicInteger(0);

	@Inject
	public OpenCryptoFile(FileCloseListener listener, Cryptor cryptor, FileHeaderHolder headerHolder, ChunkIO chunkIO, //
						  @CurrentOpenFilePaths AtomicReference<ClearAndCipherPath> currentFilePaths, @OpenFileSize AtomicLong fileSize, //
						  @OpenFileModifiedDate AtomicReference<Instant> lastModified, OpenCryptoFileComponent component) {
		this.listener = listener;
		this.cryptor = cryptor;
		this.headerHolder = headerHolder;
		this.chunkIO = chunkIO;
		this.currentFilePaths = currentFilePaths;
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
		Path path = currentFilePaths.get().ciphertextPath();
		if (path == null) {
			throw new IllegalStateException("Cannot create file channel to deleted file");
		}
		FileChannel ciphertextFileChannel = null;
		CleartextFileChannel cleartextFileChannel = null;

		openChannelsCount.incrementAndGet(); // synchronized context, hence we can proactively increase the number
		try {
			ciphertextFileChannel = path.getFileSystem().provider().newFileChannel(path, options.createOpenOptionsForEncryptedFile(), attrs);
			initFileHeader(options, ciphertextFileChannel);
			initFileSize(ciphertextFileChannel);
			cleartextFileChannel = component.newChannelComponent() //
					.create(ciphertextFileChannel, options, this::cleartextChannelClosed) //
					.channel();
			if (options.truncateExisting()) {
				cleartextFileChannel.truncate(0);
			}
		} finally {
			if (cleartextFileChannel == null) { // i.e. something didn't work
				cleartextChannelClosed(ciphertextFileChannel);
				closeQuietly(ciphertextFileChannel);
			}
		}

		assert cleartextFileChannel != null; // otherwise there would have been an exception
		chunkIO.registerChannel(ciphertextFileChannel, options.writable());
		return cleartextFileChannel;
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

	public ClearAndCipherPath getCurrentFilePaths() {
		return currentFilePaths.get();
	}

	/**
	 * Updates the current ciphertext file path, if it is not already set to null (i.e., the openCryptoFile is deleted)
	 * @param newPaths the new clear- & ciphertext paths
	 */
	public void updateCurrentFilePath(ClearAndCipherPath newPaths) {
		currentFilePaths.updateAndGet(p -> p == null ? null : newPaths);
	}

	private synchronized void cleartextChannelClosed(FileChannel ciphertextFileChannel) {
		if (ciphertextFileChannel != null) {
			chunkIO.unregisterChannel(ciphertextFileChannel);
		}
		if (openChannelsCount.decrementAndGet() == 0) {
			close();
		}
	}

	@Override
	public void close() {
		var p = currentFilePaths.get();
		if(p != null) {
			listener.close(p.ciphertextPath(), this);
		}
	}

	@Override
	public String toString() {
		return "OpenCryptoFile(path=" + currentFilePaths.get().ciphertextPath().toString() + ")";
	}
}
