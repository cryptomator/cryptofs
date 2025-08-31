package org.cryptomator.cryptofs.fh;

import jakarta.inject.Inject;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
import org.cryptomator.cryptofs.inuse.InUseManager;
import org.cryptomator.cryptofs.inuse.UseToken;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
	private final InUseManager inUseManager;
	private final Cryptor cryptor;
	private final FileHeaderHolder headerHolder;
	private final ChunkIO chunkIO;
	private final AtomicReference<Path> currentFilePath;
	private final AtomicLong fileSize;
	private final OpenCryptoFileComponent component;

	private final AtomicInteger openChannelsCount = new AtomicInteger(0);
	private volatile UseToken useToken;

	@Inject
	public OpenCryptoFile(FileCloseListener listener, Cryptor cryptor, FileHeaderHolder headerHolder, ChunkIO chunkIO, //
						  @CurrentOpenFilePath AtomicReference<Path> currentFilePath, @OpenFileSize AtomicLong fileSize, //
						  @OpenFileModifiedDate AtomicReference<Instant> lastModified, OpenCryptoFileComponent component, //
						  InUseManager inUseManager) {
		this.listener = listener;
		this.cryptor = cryptor;
		this.headerHolder = headerHolder;
		this.chunkIO = chunkIO;
		this.currentFilePath = currentFilePath;
		this.fileSize = fileSize;
		this.component = component;
		this.lastModified = lastModified;
		this.inUseManager = inUseManager;
		this.useToken = UseToken.INIT_TOKEN;
	}

	/**
	 * Creates a new file channel with the given open options.
	 *
	 * @param options The options to use to open the file channel. For the most part these will be passed through to the ciphertext channel.
	 * @return A new file channel. Ideally used in a try-with-resource statement. If the channel is not properly closed, this OpenCryptoFile will stay open indefinite.
	 * @throws IOException
	 */
	public synchronized FileChannel newFileChannel(EffectiveOpenOptions options, boolean skipUsageCheck, FileAttribute<?>... attrs) throws IOException {
		Path path = currentFilePath.get();
		if (path == null) {
			throw new IllegalStateException("Cannot create file channel to deleted file");
		}
		FileChannel ciphertextFileChannel = null;
		CleartextFileChannel cleartextFileChannel = null;

		openChannelsCount.incrementAndGet(); // synchronized context, hence we can proactively increase the number
		try {
			//TODO: what about read-only file channels? Then we need to update logic, that first writable channel needs to create this file
			if (useToken instanceof UseToken.InitToken) {
				//just an idea
			}
			useToken = inUseManager.use(path); //TODO: performance, because this causes a hashmap access
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
	 * Called by {@link #newFileChannel(EffectiveOpenOptions, boolean, FileAttribute[])} to determine the fileSize.
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
	 * @return The size of the opened file. Note that the filesize is unknown until a {@link #newFileChannel(EffectiveOpenOptions, boolean, FileAttribute[])} is opened. In this case this method returns an empty optional.
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

	public void setLastModifiedTime(FileTime lastModifiedTime) {
		lastModified.set(lastModifiedTime.toInstant());
	}

	public Path getCurrentFilePath() {
		return currentFilePath.get();
	}

	/**
	 * Updates the current ciphertext file path, if it is not already set to null (i.e., the openCryptoFile is deleted)
	 *
	 * @param newFilePath new ciphertext path
	 */
	public void updateCurrentFilePath(Path newFilePath) {
		currentFilePath.getAndUpdate(p -> p == null ? null : newFilePath);
		if (newFilePath != null) {
			useToken.moveTo(newFilePath);
		} else {
			useToken.close(); //encrypted file will be deleted, hence we can stop checking usage
		}
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
