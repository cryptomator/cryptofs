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
 * The content of the in-use-file is a JSON containing
 * <li>
 *     <ul>owner - name of the filesystem owner</ul>
 *     <ul>since - UTC-timestamp encoded as epoch seconds from the standard Java epoch of 1970-01-01T00:00:00Z</ul>
 * </li>
 * The JSON data is encrypted with the vault masterkey.
 * If the token is closed before the persistence started, the persistence is not performed.
 */
public final class RealUseToken implements UseToken {

	public static RealUseToken createWithNewFile(Path p, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens) {
		return new RealUseToken(p, owner, cryptor, useTokens, ActivationType.CREATE);
	}

	public static RealUseToken createWithExistingFile(Path p, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens) {
		return new RealUseToken(p, owner, cryptor, useTokens, ActivationType.UPDATE);
	}

	public static RealUseToken createWithInvalidFile(Path p, String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens) {
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
		FileOperation method = switch (m) {
			case STEAL -> this::stealInUseFile;
			case UPDATE -> this::updateInUseFile;
			case CREATE -> this::createInUseFile;
			case NONE -> () -> {};
		};

		if (m == ActivationType.NONE) {
			this.closed = true;
			this.creationTask = CompletableFuture.completedFuture(null);
		} else {
			this.closed = false;
			this.creationTask = CompletableFuture.runAsync(() -> {
				try {
					fileCreationSync.lock();
					if (closed) {
						return;
					}
					//Do critical stuff
					method.execute();
				} catch (IOException e) {
					close();
				} finally {
					fileCreationSync.unlock();
				}
			}, CompletableFuture.delayedExecutor(Constants.INUSE_DELAY_MILLIS, TimeUnit.MILLISECONDS, Executors.newVirtualThreadPerTaskExecutor()));
		}

	}

	private void stealInUseFile() throws IOException {
		try {
			writeInUseFile(filePath, Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING));
		} catch (IOException e) {
			LOG.warn("Failed to steal in-use file {}.", filePath, e);
			throw e;
		}
	}

	private void createInUseFile() throws IOException {
		try {
			writeInUseFile(filePath, Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW));
		} catch (IOException e) {
			LOG.warn("Failed to create in-use file {}.", filePath, e);
			throw e;
		}
	}

	private void updateInUseFile() throws IOException {
		try {
			writeInUseFile(filePath, Set.of(StandardOpenOption.WRITE));
		} catch (IOException e) {
			LOG.warn("Failed to update in-use file {}.", filePath, e);
			throw e;
		}
	}

	//TODO: refresh logic?
	void writeInUseFile(Path inUseFilePath, Set<OpenOption> openOptions) throws IOException {
		var ch = Files.newByteChannel(inUseFilePath, openOptions);
		this.channel = encWrapper.wrapWithEncryption(ch, cryptor);
		var rawInfo = new ByteArrayOutputStream(4_000);
		var prop = new Properties();
		prop.put("owner", owner);
		prop.put("since", Instant.now().toString());
		prop.store(rawInfo, null);
		channel.write(ByteBuffer.wrap(rawInfo.toByteArray()));
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
			useTokens.compute(newFilePath, (p, t) -> {
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
			useTokens.compute(filePath, (path, token) -> {
				if (channel != null) {
					try {
						channel.close();
						Files.deleteIfExists(filePath);
					} catch (IOException e) {
						//ignore
						//TODO: LOG
					}
				}
				return null;
			});
		} finally {
			fileCreationSync.unlock();
		}
	}

	enum ActivationType {
		UPDATE,
		CREATE,
		STEAL,
		NONE;
	}

	@FunctionalInterface
	interface FileOperation {

		void execute() throws IOException;
	}

	interface EncryptionDecorator {

		WritableByteChannel wrapWithEncryption(ByteChannel ch, Cryptor c);
	}
}
