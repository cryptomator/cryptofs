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
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Class to represent a file is "in use" by this filesystem.
 * <p>
 * The actual persistence of the "in use"-state with a file is delayed by {@value Constants#INUSE_DELAY_MILLIS} milliseconds.
 * If the token is closed before it is persisted with a file, writing it to disk is skipped.
 */
public final class RealUseToken implements UseToken {

	public static RealUseToken createWithNewFile(Path p, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens) {
		return new RealUseToken(p, owner, cryptor, useTokens, ActivationType.CREATE);
	}

	public static RealUseToken createWithExistingFile(Path p, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens) {
		return new RealUseToken(p, owner, cryptor, useTokens, ActivationType.STEAL);
	}

	public static RealUseToken createInvalid(Path p, ConcurrentMap<Path, RealUseToken> useTokens) {
		return new RealUseToken(p, "unused", null, useTokens, ActivationType.NONE);
	}

	private static final Logger LOG = LoggerFactory.getLogger(RealUseToken.class);

	private final String owner;
	private final CompletableFuture<Void> creationTask;
	private final Cryptor cryptor;
	private final ConcurrentMap<Path, RealUseToken> useTokens;
	private final EncryptionDecorator encWrapper; //this exists to make the class testable
	private final ReentrantReadWriteLock.WriteLock fileCreationSync = new ReentrantReadWriteLock().writeLock();

	private volatile Path filePath;
	private volatile WritableByteChannel channel;
	private volatile boolean closed;

	RealUseToken(Path filePath, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens, ActivationType m) {
		this(filePath, owner, cryptor, useTokens, m, EncryptedChannels::wrapEncryptionAround);
	}

	RealUseToken(Path filePath, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens, ActivationType m, EncryptionDecorator encWrapper) {
		this.owner = owner;
		this.filePath = filePath;
		this.cryptor = cryptor;
		this.useTokens = useTokens;
		this.encWrapper = encWrapper;
		Set<OpenOption> openOptions = switch (m) {
			case STEAL -> Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
			case CREATE -> Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
			case NONE -> Set.of();
		};

		if (m == ActivationType.NONE) {
			this.closed = true;
			this.creationTask = CompletableFuture.completedFuture(null);
		} else {
			this.closed = false;
			this.creationTask = CompletableFuture.runAsync(() -> createInUseFile(openOptions), CompletableFuture.delayedExecutor(Constants.INUSE_DELAY_MILLIS, TimeUnit.MILLISECONDS, Executors.newVirtualThreadPerTaskExecutor()));
		}

	}

	private void createInUseFile(Set<OpenOption> openOptions) {
		try {
			fileCreationSync.lock();
			if (closed) {
				return;
			}
			var ch = Files.newByteChannel(filePath, openOptions);
			this.channel = encWrapper.wrapWithEncryption(ch, cryptor);
			writeInUseFile();
		} catch (IOException e) {
			LOG.debug("Failed to write in-use file {} with open options {}.", filePath, openOptions, e);
			close();
		} finally {
			fileCreationSync.unlock();
		}

	}

	void refresh() {
		var oldChannel = channel;
		createInUseFile(Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING));

		try {
			oldChannel.close();
		} catch (IOException e) {
			LOG.warn("Failed to close stale channel to in-use-file {}", filePath, e);
		}
	}

	int writeInUseFile() throws IOException {
		var rawInfo = new ByteArrayOutputStream(Constants.INUSE_CLEARTEXT_SIZE);
		var prop = new Properties();
		prop.put(UseToken.OWNER_KEY, owner);
		prop.put(UseToken.LASTUPDATED_KEY, Instant.now().toString());
		prop.store(rawInfo, null);
		return channel.write(ByteBuffer.wrap(rawInfo.toByteArray()));
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
			LOG.warn("Failed to move in-use file {} to {}.", filePath, newFilePath, e.getCause());
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
						LOG.info("Failed to delete inUse File {}. Must be deleted manually.", path);
					}
				}
				return null;
			});
		} finally {
			fileCreationSync.unlock();
		}
	}

	enum ActivationType {
		CREATE,
		STEAL,
		NONE;
	}

	interface EncryptionDecorator {

		WritableByteChannel wrapWithEncryption(ByteChannel ch, Cryptor c);
	}
}
