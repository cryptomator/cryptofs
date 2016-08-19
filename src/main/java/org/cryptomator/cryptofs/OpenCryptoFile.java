package org.cryptomator.cryptofs;

import static java.lang.Math.min;
import static org.cryptomator.cryptofs.OpenCounter.OpenState.ALREADY_CLOSED;
import static org.cryptomator.cryptofs.OpenCounter.OpenState.WAS_OPEN;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import org.cryptomator.cryptofs.OpenCounter.OpenState;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

class OpenCryptoFile {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoFileChannel.class);
	private static final int MAX_CACHED_CLEARTEXT_CHUNKS = 5;

	private final Cryptor cryptor;
	private final Path path;
	private final FileChannel channel;
	private final FileHeader header;
	private final LoadingCache<Long, ChunkData> cleartextChunks;
	private final AtomicLong size;
	private final Consumer<OpenCryptoFile> onClosed;
	private final Collection<IOException> ioExceptionsDuringWrite = new ArrayList<>();
	private final OpenCounter openCounter = new OpenCounter();

	/**
	 * Only one OpenCryptoFile instance for each file exists at a time.
	 * Therefore there must not be any reference to any equal instance, when this instance is constructed.
	 * I.e. immediately after construction the unique ID of this OpenCryptoFile will get cached for future reference.
	 */
	public OpenCryptoFile(Builder builder) throws IOException {
		this.cryptor = builder.cryptor;
		this.path = builder.path;
		this.channel = path.getFileSystem().provider().newFileChannel(path, builder.options.createOpenOptionsForEncryptedFile());
		this.header = createOrLoadHeader(builder.options);
		this.size = new AtomicLong(header.getFilesize());
		this.cleartextChunks = CacheBuilder.newBuilder() //
				.maximumSize(MAX_CACHED_CLEARTEXT_CHUNKS) //
				.removalListener(new CleartextChunkSaver()) //
				.build(new CleartextChunkLoader());
		this.onClosed = builder.onClosed;
	}

	private FileHeader createOrLoadHeader(EffectiveOpenOptions options) throws IOException {
		if (options.truncateExisting() || isNewFile(options)) {
			return cryptor.fileHeaderCryptor().create();
		} else {
			ByteBuffer existingHeaderBuf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
			channel.position(0);
			channel.read(existingHeaderBuf);
			existingHeaderBuf.flip();
			return cryptor.fileHeaderCryptor().decryptHeader(existingHeaderBuf);
		}
	}

	private boolean isNewFile(EffectiveOpenOptions options) throws IOException {
		return options.createNew() || options.create() && channel.size() == 0;
	}

	public Path path() {
		return path;
	}

	public synchronized int read(ByteBuffer dst, long position) throws IOException {
		int origLimit = dst.limit();
		long limitConsideringEof = size() - position;
		if (limitConsideringEof < 1) {
			return -1;
		}
		dst.limit((int) Math.min(origLimit, limitConsideringEof));
		int read = 0;
		int payloadSize = cryptor.fileContentCryptor().cleartextChunkSize();
		while (dst.hasRemaining()) {
			long pos = position + read;
			long chunkIndex = pos / payloadSize;
			int offset = (int) pos % payloadSize;
			int len = Math.min(dst.remaining(), payloadSize - offset);
			final ChunkData chunkData = loadCleartextChunk(chunkIndex);
			chunkData.copyDataStartingAt(offset).to(dst);
			read += len;
		}
		dst.limit(origLimit);
		return read;
	}

	public synchronized long append(EffectiveOpenOptions options, ByteBuffer src) throws IOException {
		return write(options, src, size());
	}

	public synchronized int write(EffectiveOpenOptions options, ByteBuffer data, long offset) throws IOException {
		long size = size();
		int written = data.remaining();
		if (size < offset) {
			// fill gap between size and offset with zeroes
			write(ByteSource.repeatingZeroes(offset - size).followedBy(data), size);
		} else {
			write(ByteSource.from(data), offset);
		}
		handleSync(options);
		return written;
	}

	private void handleSync(EffectiveOpenOptions options) throws IOException {
		if (options.syncData()) {
			force(options.syncDataAndMetadata(), options.writable());
		}
	}

	private void write(ByteSource source, long position) {
		int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
		int written = 0;
		while (source.hasRemaining()) {
			long currentPosition = position + written;
			long chunkIndex = currentPosition / cleartextChunkSize;
			int offsetInChunk = (int) currentPosition % cleartextChunkSize;
			int len = (int) min(source.remaining(), cleartextChunkSize - offsetInChunk);
			if (currentPosition + len > size()) {
				// append
				setSize(currentPosition + len);
			}
			if (len == cleartextChunkSize) {
				// complete chunk, no need to load and decrypt from file:
				cleartextChunks.put(chunkIndex, ChunkData.emptyWithSize(cleartextChunkSize));
			}
			final ChunkData chunkData = loadCleartextChunk(chunkIndex);
			chunkData.copyDataStartingAt(offsetInChunk).from(source);
			written += len;
		}
	}

	public long size() {
		return size.get();
	}

	private void setSize(long size) {
		this.size.set(size);
	}

	public synchronized void truncate(long size) throws IOException {
		// TODO
	}

	public synchronized void force(boolean metaData, boolean flushContents) throws IOException {
		cleartextChunks.invalidateAll();
		if (flushContents) {
			header.setFilesize(size.get());
			channel.write(cryptor.fileHeaderCryptor().encryptHeader(header), 0);
		}
		channel.force(metaData);
	}

	public FileLock lock(long position, long size, boolean shared) throws IOException {
		// TODO compute correct position / size
		return channel.lock(position, size, shared);
	}

	public FileLock tryLock(long position, long size, boolean shared) throws IOException {
		// TODO compute correct position / size
		return channel.tryLock(position, size, shared);
	}

	private ChunkData loadCleartextChunk(long chunkIndex) {
		try {
			return cleartextChunks.get(chunkIndex);
		} catch (ExecutionException e) {
			if (e.getCause() instanceof AuthenticationFailedException) {
				// TODO provide means to pass an AuthenticationFailedException handler using an OpenOption
				throw new UnsupportedOperationException("TODO", e);
			} else {
				throw new IllegalStateException("Unexpected Exception.", e);
			}
		}
	}

	private class CleartextChunkLoader extends CacheLoader<Long, ChunkData> {

		@Override
		public ChunkData load(Long chunkIndex) throws Exception {
			LOG.debug("load chunk" + chunkIndex);
			int payloadSize = cryptor.fileContentCryptor().cleartextChunkSize();
			int chunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
			long ciphertextPos = chunkIndex * chunkSize + cryptor.fileHeaderCryptor().headerSize();
			ByteBuffer ciphertextBuf = ByteBuffer.allocate(chunkSize);
			int read = channel.read(ciphertextBuf, ciphertextPos);
			if (read == -1) {
				// append
				return ChunkData.emptyWithSize(payloadSize);
			} else {
				ciphertextBuf.flip();
				return ChunkData.wrap(cryptor.fileContentCryptor().decryptChunk(ciphertextBuf, chunkIndex, header, true));
			}
		}

	}

	private class CleartextChunkSaver implements RemovalListener<Long, ChunkData> {

		@Override
		public void onRemoval(RemovalNotification<Long, ChunkData> notification) {
			onRemoval(notification.getKey(), notification.getValue());
		}

		private void onRemoval(long chunkIndex, ChunkData chunkData) {
			if (chunkLiesInFile(chunkIndex) && chunkData.wasWritten()) {
				LOG.debug("save chunk" + chunkIndex);
				long ciphertextPos = chunkIndex * cryptor.fileContentCryptor().ciphertextChunkSize() + cryptor.fileHeaderCryptor().headerSize();
				ByteBuffer cleartextBuf = chunkData.asReadOnlyBuffer();
				ByteBuffer ciphertextBuf = cryptor.fileContentCryptor().encryptChunk(cleartextBuf, chunkIndex, header);
				try {
					channel.write(ciphertextBuf, ciphertextPos);
				} catch (IOException e) {
					ioExceptionsDuringWrite.add(e);
				} // unchecked exceptions will be propagated to the thread causing removal
			}
		}

		private boolean chunkLiesInFile(long chunkIndex) {
			return chunkIndex * cryptor.fileContentCryptor().cleartextChunkSize() < size();
		}

	}

	public void open(EffectiveOpenOptions openOptions) throws IOException {
		OpenState state = openCounter.countOpen();
		if (state == ALREADY_CLOSED) {
			throw new ClosedChannelException();
		} else if (state == WAS_OPEN && openOptions.createNew()) {
			throw new IOException("Failed to create new file. File exists.");
		}
	}

	public void close(boolean flushContents) throws IOException {
		force(true, flushContents);
		if (openCounter.countClose()) {
			try {
				onClosed.accept(this);
			} finally {
				try {
					channel.close();
				} finally {
					cryptor.destroy();
				}
			}
		}
	}

	public static Builder anOpenCryptoFile() {
		return new Builder();
	}

	public static class Builder {

		private Cryptor cryptor;
		private Path path;
		private EffectiveOpenOptions options;
		private Consumer<OpenCryptoFile> onClosed = ignored -> {
		};

		private Builder() {
		}

		public Builder withCryptor(Cryptor cryptor) {
			this.cryptor = cryptor;
			return this;
		}

		public Builder withPath(Path path) {
			this.path = path;
			return this;
		}

		public Builder withOptions(EffectiveOpenOptions options) {
			this.options = options;
			return this;
		}

		public Builder onClosed(Consumer<OpenCryptoFile> onClosed) {
			this.onClosed = onClosed;
			return this;
		}

		public OpenCryptoFile build() throws IOException {
			validate();
			return new OpenCryptoFile(this);
		}

		private void validate() {
			assertNonNull(cryptor, "cryptor");
			assertNonNull(path, "path");
			assertNonNull(options, "options");
			assertNonNull(onClosed, "onClosed");
		}

		private void assertNonNull(Object value, String name) {
			if (value == null) {
				throw new IllegalStateException(name + " must not be empty");
			}
		}

	}

}
