package org.cryptomator.cryptofs.fh;

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
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentMap;
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


	private UseToken(Path p, ConcurrentMap<Path, UseToken> useTokens, ActivationType m, Cryptor cryptor,) {
		this.p = p;
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
				closed = true;
			} finally {
				fileCreationSync.unlock();
			}
		}); //TODO: delayed executor
	}

	private final CompletableFuture<Void> creationTask;
	private final ConcurrentMap<Path, UseToken> useTokens;
	private final ReentrantReadWriteLock.WriteLock fileCreationSync = new ReentrantReadWriteLock().writeLock();

	private volatile Path p;
	private volatile SeekableByteChannel channel;
	private volatile boolean closed = false;


	private void stealInUseFile() {
		try {
			writeInUseFile(p, Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING));
		} catch (IOException e) {
			//LOG.warn("Failed to create in-use file for {}.", inUseFilePath, e);
		}
	}

	private void createInUseFile() {
		try {
			writeInUseFile(p, Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW));
		} catch (IOException e) {
			//LOG.warn("Failed to create in-use file for {}.", inUseFilePath, e);
		}
	}

	private void updateInUseFile() {
		try {
			writeInUseFile(p, Set.of(StandardOpenOption.WRITE));
		} catch (IOException e) {
			//LOG.warn("Failed to create in-use file for {}.", inUseFilePath, e);
		}
	}

	boolean writeInUseFile(Path inUseFilePath, Set<OpenOption> openOptions) throws IOException {
		this.channel = Files.newByteChannel(inUseFilePath, openOptions); //TODO: delete on close?
		var rawInfo = new ByteArrayOutputStream(4_000);
		new Properties().store(rawInfo, "UNENCRYPTED Cryptomator inUse file");
		//TODO: encryption
		channel.write(ByteBuffer.wrap(rawInfo.toByteArray()));
		channel.position(0);
		return true;
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
					Files.move(p, newPath, StandardCopyOption.REPLACE_EXISTING);
					return this;
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			});
			useTokens.remove(p);
			this.p = newPath;
		} catch (UncheckedIOException e) {
			//TODO: Log
			close(); //To prevent invalid states
		} finally {
			fileCreationSync.unlock();
		}
	}


	@Override
	public void close() {
		try {
			//sync with file creation
			fileCreationSync.lock();

			if (closed) {
				return;
			}
			creationTask.cancel(false);
			useTokens.compute(p, (path, token) -> {
				closed = true;
				if (channel != null) {
					try {
						channel.close();
					} catch (IOException e) {
						//ignore
					}
					//delete file if channel != null
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
