package org.cryptomator.cryptofs.fh;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
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

public class UseToken implements Closeable {

	public static UseToken createWithNewFile(Path p, ConcurrentMap<Path, UseToken> useTokens) {
		return new UseToken(p, useTokens, ActivationType.CREATE);
	}

	public static UseToken createWithExistingFile(Path p, ConcurrentMap<Path, UseToken> useTokens) {
		return new UseToken(p, useTokens, ActivationType.UPDATE);
	}

	public static UseToken createWithExistingInvalidFile(Path p, ConcurrentMap<Path, UseToken> useTokens) {
		return new UseToken(p, useTokens, ActivationType.STEAL);
	}

	private static final Logger LOG = LoggerFactory.getLogger(UseToken.class);

	private final CompletableFuture<Void> creationTask;
	private final ConcurrentMap<Path, UseToken> useTokens;
	private final ReentrantReadWriteLock.WriteLock fileCreationSync = new ReentrantReadWriteLock().writeLock();

	private volatile Path filePath;
	private volatile SeekableByteChannel channel;
	private volatile boolean closed = false;

	private UseToken(Path filePath, ConcurrentMap<Path, UseToken> useTokens, ActivationType m) {
		this.filePath = filePath;
		this.useTokens = useTokens;
		FileOperation method = switch (m) {
			case STEAL -> this::stealInUseFile;
			case UPDATE -> this::updateInUseFile;
			case CREATE -> this::createInUseFile;
		};

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
		}, CompletableFuture.delayedExecutor(5, TimeUnit.SECONDS, Executors.newVirtualThreadPerTaskExecutor()));
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

	void writeInUseFile(Path inUseFilePath, Set<OpenOption> openOptions) throws IOException {
		this.channel = Files.newByteChannel(inUseFilePath, openOptions);
		var rawInfo = new ByteArrayOutputStream(4_000);
		var prop = new Properties();
		prop.put("owner", "owner"); //TODO: add real info
		prop.put("owningSince", Instant.now().toString());
		prop.store(rawInfo, "UNENCRYPTED Cryptomator inUse file");
		//TODO: encryption
		channel.write(ByteBuffer.wrap(rawInfo.toByteArray()));
		channel.position(0);
	}

	void move(Path newPath) {
		try {
			//sync with file creation
			fileCreationSync.lock();

			if (closed) {
				return;
			}
			useTokens.compute(newPath, (p, t) -> {
				try {
					if (channel != null) {
						Files.move(filePath, newPath, StandardCopyOption.REPLACE_EXISTING);
					}
					return this;
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			});
			useTokens.remove(filePath);
			this.filePath = newPath;
		} catch (UncheckedIOException e) {
			LOG.warn("Failed to move in-use file {} to {}.", filePath, newPath, e.getCause());
			close(); //To prevent invalid states
		} finally {
			fileCreationSync.unlock();
		}
	}

	boolean isClosed() {
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
		STEAL;
	}

	@FunctionalInterface
	interface FileOperation {

		void execute() throws IOException;
	}
}
