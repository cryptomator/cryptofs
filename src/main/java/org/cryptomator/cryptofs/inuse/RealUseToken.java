package org.cryptomator.cryptofs.inuse;

import org.cryptomator.cryptofs.common.EncryptedChannels;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.FileChannel;
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
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Class to represent a file is "in use" by this filesystem.
 * <p>
 * The actual persistence of the "in use"-state with a file is delayed by {@value CREATION_DELAY_MILLIS} milliseconds.
 * The file is regularly rewritten with lastUpdated updated to the current time. This is done with an exponential backoff strategy, but at latest after {@value UseToken#STALE_THRESHOLD_MINUTES} minutes.
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
	private static final Semaphore CONCURRENT_WRITES_SEMAPHORE = new Semaphore(20);
	private static final int CREATION_DELAY_MILLIS = 5000;
	private static final int MAX_REFRESH_DELAY_SECONDS = 300;

	private final String owner;
	private final AtomicReference<CompletableFuture<Void>> tokenPersistenceTask = new AtomicReference<>();
	private final Executor tokenPersistor;
	private final Cryptor cryptor;
	private final ConcurrentMap<Path, RealUseToken> useTokens;
	private final EncryptionDecorator encWrapper; //this exists to make the class testable
	private final ReentrantReadWriteLock.WriteLock fileCreationSync = new ReentrantReadWriteLock().writeLock();

	private volatile Path filePath;
	private volatile FileChannel channel;
	private volatile boolean closed;
	private volatile long lastModified;

	RealUseToken(Path filePath, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens, Executor tokenPersistor, OpenOption openMode) {
		this(filePath, owner, cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, openMode, EncryptedChannels::wrapEncryptionAround);
	}

	RealUseToken(Path filePath, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens, Executor tokenPersistor, int creationDelayMillis, OpenOption openMode, EncryptionDecorator encWrapper) {
		this.owner = owner;
		this.filePath = filePath;
		this.cryptor = cryptor;
		this.useTokens = useTokens;
		this.encWrapper = encWrapper;
		this.closed = false;
		this.tokenPersistor = tokenPersistor;

		var openOptions = Set.of(StandardOpenOption.WRITE, openMode);
		var delayedExecutor = CompletableFuture.delayedExecutor(creationDelayMillis, TimeUnit.MILLISECONDS, tokenPersistor);
		var creationTask = CompletableFuture.runAsync(() -> createInUseFile(openOptions), delayedExecutor);
		this.tokenPersistenceTask.set(creationTask);
		scheduleRefresh(0);
	}

	//TODO test?
	private void scheduleRefresh(int count) {
		var currentTask = tokenPersistenceTask.get();
		if (closed || currentTask.isCancelled()) {
			return;
		}

		var delayedExecutor = delayExponentiallyWithCap(tokenPersistor, count);
		var nextPersistenceTask = currentTask.thenRunAsync(() -> runRefresh(count), delayedExecutor);
		tokenPersistenceTask.set(nextPersistenceTask);
	}

	private void runRefresh(int count) {
		try {
			CONCURRENT_WRITES_SEMAPHORE.acquire();
			try {
				refresh();
				scheduleRefresh(count + 1);
			} finally {
				CONCURRENT_WRITES_SEMAPHORE.release();
			}
		} catch (InterruptedException e) {
			LOG.warn("Interrupt during refresh of {}. Closing token.", filePath);
			close();
			Thread.currentThread().interrupt();
			throw new RuntimeException(e); //mark the completion stage as failed
		}
	}

	private Executor delayExponentiallyWithCap(Executor executor, int count) {
		//0:15s, 1:30s, 2:60s=1min, 3:120s=2min, 4:240s=4min, else:300s=5min
		var delay = count > 4 ? MAX_REFRESH_DELAY_SECONDS : 15 * Math.powExact(2, count);
		return CompletableFuture.delayedExecutor(delay, TimeUnit.SECONDS, executor);
	}

	private void createInUseFile(Set<OpenOption> openOptions) {
		fileCreationSync.lock();
		try {
			if (closed) {
				return;
			}
			this.channel = FileChannel.open(filePath, openOptions);
			writeInUseFile();
		} catch (IOException e) {
			LOG.debug("Failed to write in-use file {} with open options {}.", filePath, openOptions, e);
			close();
		} finally {
			fileCreationSync.unlock();
		}

	}

	void refresh() {
		fileCreationSync.lock();
		try {
			if (closed || channel == null) {
				return;
			}
			var currentLastModfied = Files.getLastModifiedTime(filePath).toMillis();
			if (currentLastModfied != lastModified) {
				throw new ModifiedFileException(); //someone edited _our_ file.
			}
			writeInUseFile();
		} catch (ModifiedFileException e) {
			LOG.debug("Failed to refresh in-use file {}.", filePath, e);
			close(false);
		} catch (IOException e) {
			LOG.debug("Failed to refresh in-use file {}.", filePath, e);
			close();
		} finally {
			fileCreationSync.unlock();
		}
	}

	int writeInUseFile() throws IOException {
		channel.truncate(0);
		final int bytesWritten;
		try (var nonClosingWrapper = new NonClosingByteChannel(channel); //
			 var encChannel = encWrapper.wrapWithEncryption(nonClosingWrapper, cryptor)) {
			var rawInfo = new ByteArrayOutputStream(UseToken.MAX_CLEARTEXT_SIZE_BYTES);
			var prop = new Properties();
			prop.put(UseToken.OWNER_KEY, owner);
			prop.put(UseToken.LASTUPDATED_KEY, Instant.now().toString());
			prop.store(rawInfo, null);
			bytesWritten = encChannel.write(ByteBuffer.wrap(rawInfo.toByteArray()));
		}
		channel.force(true);
		lastModified = Files.getLastModifiedTime(filePath).toMillis();
		return bytesWritten;
	}

	@Override
	public void moveTo(Path newCiphertextPath) {
		var inUseFilePath = RealInUseManager.computeInUseFilePath(newCiphertextPath);
		moveToInternal(inUseFilePath);
	}

	//visible for testing
	void moveToInternal(Path newFilePath) {
		fileCreationSync.lock();
		try {
			if (closed) {
				return;
			}
			useTokens.compute(newFilePath, (_, _) -> {
				try {
					if (channel != null) {
						//normally, moving a file retains lastModified. If not, the file will fail the refresh test and will be closed.
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
		close(true);
	}

	void close(boolean deleteFile) {
		fileCreationSync.lock();
		try {
			if (closed) {
				return;
			}
			closed = true;
			tokenPersistenceTask.get().cancel(false);
			useTokens.compute(filePath, (path, _) -> {
				if (channel != null) {
					try {
						channel.close();
						if (deleteFile) {
							Files.deleteIfExists(filePath);
						}
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

	//--- glue code ---

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

	static class ModifiedFileException extends RuntimeException {

	}
}
