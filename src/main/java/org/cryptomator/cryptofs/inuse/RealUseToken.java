package org.cryptomator.cryptofs.inuse;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.EncryptedChannels;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Class to represent a file is "in use" by this filesystem.
 * <p>
 * The actual persistence of the "in use"-state with a file is delayed by {@value Constants#INUSE_DELAY_MILLIS} milliseconds.
 * If the token is closed before it is persisted with a file, writing it to disk is skipped.
 */
public final class RealUseToken implements UseToken {

	public static RealUseToken createWithNewFile(Path p, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens, Executor tokenPersistor) {
		return new RealUseToken(p, owner, cryptor, useTokens, tokenPersistor, StandardOpenOption.CREATE_NEW);
	}

	public static RealUseToken createWithExistingFile(Path p, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens, Executor tokenPersistor) {
		return new RealUseToken(p, owner, cryptor, useTokens, tokenPersistor, StandardOpenOption.TRUNCATE_EXISTING);
	}

	private static final Logger LOG = LoggerFactory.getLogger(RealUseToken.class);

	private final String owner;
	private final CompletableFuture<Void> creationTask;
	private final Cryptor cryptor;
	private final ConcurrentMap<Path, RealUseToken> useTokens;
	private final EncryptionDecorator encWrapper; //this exists to make the class testable
	private final ReentrantReadWriteLock.WriteLock fileCreationSync = new ReentrantReadWriteLock().writeLock();

	private volatile Path filePath;
	private volatile SeekableByteChannel channel;
	private volatile boolean closed;

	RealUseToken(Path filePath, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens, Executor tokenPersistor, OpenOption openMode) {
		var delayedExecutor = CompletableFuture.delayedExecutor(Constants.INUSE_DELAY_MILLIS, TimeUnit.MILLISECONDS, tokenPersistor);
		this(filePath, owner, cryptor, useTokens, delayedExecutor, openMode, EncryptedChannels::wrapEncryptionAround);
	}

	RealUseToken(Path filePath, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens, Executor tokenPersistor, OpenOption openMode, EncryptionDecorator encWrapper) {
		this.owner = owner;
		this.filePath = filePath;
		this.cryptor = cryptor;
		this.useTokens = useTokens;
		this.encWrapper = encWrapper;
		this.closed = false;
		var openOptions = Set.of(StandardOpenOption.WRITE, openMode);
		this.creationTask = CompletableFuture.runAsync(() -> createInUseFile(openOptions), tokenPersistor);

	}

	private void createInUseFile(Set<OpenOption> openOptions) {
		try {
			fileCreationSync.lock();
			if (closed) {
				return;
			}
			this.channel = Files.newByteChannel(filePath, openOptions);
			writeInUseFile();
		} catch (IOException e) {
			LOG.debug("Failed to write in-use file {} with open options {}.", filePath, openOptions, e);
			close();
		} finally {
			fileCreationSync.unlock();
		}

	}

	void refresh() {
		try {
			fileCreationSync.lock();
			if (closed || channel == null) {
				return;
			}
			writeInUseFile();
			channel.position(0);
		} catch (IOException e) {
			LOG.debug("Failed to refresh in-use file {}.", filePath, e);
		} finally {
			fileCreationSync.unlock();
		}
	}

	int writeInUseFile() throws IOException {
		try (var nonClosingWrapper = new NonClosingByteChannel(channel); //
			 var encChannel = encWrapper.wrapWithEncryption(nonClosingWrapper, cryptor)) {
			var rawInfo = new ByteArrayOutputStream(Constants.INUSE_CLEARTEXT_SIZE);
			var prop = new Properties();
			prop.put(UseToken.OWNER_KEY, owner);
			prop.put(UseToken.LASTUPDATED_KEY, Instant.now().toString());
			prop.store(rawInfo, "Cryptomator Use Info");
			return encChannel.write(ByteBuffer.wrap(rawInfo.toByteArray()));
		}
	}

	@Override
	public void moveTo(Path newCiphertextPath) {
		var inUseFilePath = RealInUseManager.computeInUseFilePath(newCiphertextPath);
		moveToInternal(inUseFilePath);
	}

	//visible for testing
	void moveToInternal(Path newFilePath) {
		try {
			//sync with file creation
			fileCreationSync.lock();

			if (closed) {
				return;
			}
			useTokens.compute(newFilePath, (_, _) -> {
				try {
					if (channel != null) {
						Files.move(filePath, newFilePath, StandardCopyOption.REPLACE_EXISTING);
					}
					return this;
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			});
			useTokens.remove(filePath);
			this.filePath = newFilePath;
		} catch (UncheckedIOException e) {
			LOG.debug("Failed to move in-use file {} to {}.", filePath, newFilePath, e.getCause());
			close(); //To prevent invalid states
		} finally {
			fileCreationSync.unlock();
		}
	}

	@Override
	public boolean isClosed() {
		return closed;
	}

	@Override
	public void close() {
		try {
			//sync with file creation
			fileCreationSync.lock();

			if (closed) {
				return;
			}
			closed = true;
			creationTask.cancel(false);
			useTokens.compute(filePath, (path, _) -> {
				if (channel != null) {
					try {
						channel.close();
						Files.deleteIfExists(filePath);
					} catch (IOException e) {
						//ignore
						LOG.warn("Failed to delete inUse File {}. Must be deleted manually.", path);
					}
				}
				return null;
			});
		} finally {
			fileCreationSync.unlock();
		}
	}

	interface EncryptionDecorator {

		WritableByteChannel wrapWithEncryption(ByteChannel ch, Cryptor c);
	}

	record NonClosingByteChannel(ByteChannel delegate) implements ByteChannel {

		@Override
		public int write(ByteBuffer src) throws IOException {
			return delegate.write(src);
		}

		@Override
		public boolean isOpen() {
			return delegate.isOpen();
		}

		@Override
		public void close() throws IOException {
			//no-op
		}

		@Override
		public int read(ByteBuffer dst) throws IOException {
			return delegate.read(dst);
		}
	}
}
