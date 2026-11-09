/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.fh;

import jakarta.inject.Inject;
import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.common.RunnableThrowingException;
import org.cryptomator.cryptofs.common.SupplierThrowingException;
import org.cryptomator.cryptofs.event.FilesystemEvent;

import java.io.Closeable;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;
import java.util.function.Consumer;
import java.util.stream.Stream;

@CryptoFileSystemScoped
public class OpenCryptoFiles implements Closeable {

	private final OpenCryptoFileComponent.Factory openCryptoFileComponentFactory;
	private final Consumer<FilesystemEvent> eventConsumer;
	private final ConcurrentMap<Path, OpenCryptoFile> openCryptoFiles = new ConcurrentHashMap<>();
	private final ConcurrentMap<Path, PathLock> pathLocks = new ConcurrentHashMap<>();

	@Inject
	OpenCryptoFiles(OpenCryptoFileComponent.Factory openCryptoFileComponentFactory, Consumer<FilesystemEvent> eventConsumer) {
		this.openCryptoFileComponentFactory = openCryptoFileComponentFactory;
		this.eventConsumer = eventConsumer;
	}

	/**
	 * Gets an OpenCryptoFile (if any is opened) without creating it.
	 * <p>
	 * Useful if you don't want to create any FileChannel but want to check whether this file is currently opened (e.g. to get its current {@link OpenCryptoFile#size()}).
	 *
	 * @param ciphertextPath Path of the file which might have been opened
	 * @return The OpenCryptoFile if opened or an empty Optional otherwise.
	 */
	public Optional<OpenCryptoFile> get(Path ciphertextPath) {
		Path normalizedPath = normalize(ciphertextPath);
		return Optional.ofNullable(openCryptoFiles.get(normalizedPath));
	}

	/**
	 * Gets the shared OpenCryptoFile of the given file, creating it if necessary.
	 * Getting the file channel should be the next invocation, since the {@link OpenFileScoped lifecycle} of the OpenFile strictly depends on the lifecycle of the channel.
	 *
	 * @param ciphertextPath Path of the file to open
	 * @return The opened file.
	 * @see #newFileChannel(CryptoPath, Path, EffectiveOpenOptions, FileAttribute[])
	 */
	OpenCryptoFile getOrCreate(Path ciphertextPath) {
		Path normalizedPath = normalize(ciphertextPath);
		return openCryptoFiles.computeIfAbsent(normalizedPath, p -> openCryptoFileComponentFactory.create(p, openCryptoFiles::remove).openCryptoFile()); // computeIfAbsent is atomic, "create" is called at most once
	}

	/**
	 * Runs an operation that opens the given file, waiting while this file is the source or target of a {@link #prepareMove(Path, Path, CryptoPath, boolean, Path...) move} or the target of a {@link #replace(Path, RunnableThrowingException) replacement}.
	 * A {@link org.cryptomator.cryptofs.event.DecryptionFailedEvent} of a file header that cannot be decrypted is delivered after the lock was released, so that event consumers may access the file system.
	 * The operation must let exceptions of {@link #newFileChannel(CryptoPath, Path, EffectiveOpenOptions, FileAttribute[])} propagate unwrapped.
	 * Any other event must be emitted by the caller after this method returned.
	 *
	 * @param ciphertextPath Path of the file to open
	 * @param operation The open operation, which may invoke {@link #newFileChannel(CryptoPath, Path, EffectiveOpenOptions, FileAttribute[])} for this path
	 * @param <T> Result type of the operation
	 * @return The result of the operation
	 * @throws IOException If the operation failed
	 */
	public <T> T open(Path ciphertextPath, SupplierThrowingException<T, IOException> operation) throws IOException {
		try {
			Runnable unlock = lockPaths(List.of(ciphertextPath), lock -> lock.readLock());
			try {
				return operation.get();
			} finally {
				unlock.run();
			}
		} catch (HeaderDecryptionException e) {
			eventConsumer.accept(e.getEvent());
			throw e;
		}
	}

	/**
	 * Opens a new FileChannel using the shared OpenCryptoFile of the given file.
	 * MUST be invoked within an {@link #open(Path, SupplierThrowingException) open operation} of the same path.
	 * The channel is not truncated, even if the options contain {@link java.nio.file.StandardOpenOption#TRUNCATE_EXISTING}.
	 * The caller must truncate it after the open operation returned, because truncation waits for readers of the file, which may in turn wait for the lock held during the open operation.
	 *
	 * @param cleartextPath Cleartext path of the file to open
	 * @param ciphertextPath Path of the file to open
	 * @param options The options to open the file channel with
	 * @param attrs The file attributes to set when creating the file
	 * @return A new file channel
	 * @throws IOException If the file channel could not be opened
	 */
	public FileChannel newFileChannel(CryptoPath cleartextPath, Path ciphertextPath, EffectiveOpenOptions options, FileAttribute<?>... attrs) throws IOException {
		PathLock pathLock = pathLocks.get(normalize(ciphertextPath));
		if (pathLock == null || pathLock.lock.getReadHoldCount() == 0) {
			throw new IllegalStateException("Not invoked within an open operation of " + ciphertextPath);
		}
		OpenCryptoFile openFile = getOrCreate(ciphertextPath);
		openFile.updateCurrentCleartextPath(cleartextPath);
		return openFile.newFileChannel(options, attrs);
	}

	public void writeCiphertextFile(CryptoPath cleartextPath, Path ciphertextPath, EffectiveOpenOptions openOptions, ByteBuffer contents) throws IOException {
		try (FileChannel ch = open(ciphertextPath, () -> newFileChannel(cleartextPath, ciphertextPath, openOptions))) {
			if (openOptions.truncateExisting()) {
				ch.truncate(0);
			}
			ch.write(contents);
		}
	}

	public ByteBuffer readCiphertextFile(CryptoPath cleartextPath, Path ciphertextPath, EffectiveOpenOptions openOptions, int maxBufferSize) throws BufferUnderflowException, IOException {
		try (FileChannel ch = open(ciphertextPath, () -> newFileChannel(cleartextPath, ciphertextPath, openOptions))) {
			if (ch.size() > maxBufferSize) {
				throw new BufferUnderflowException();
			}
			ByteBuffer buf = ByteBuffer.allocate((int) ch.size()); // ch.size() <= maxBufferSize <= Integer.MAX_VALUE
			ch.read(buf);
			buf.flip();
			return buf;
		}
	}

	/**
	 * Removes a ciphertextPath to {@link OpenCryptoFile} mapping, if it exists, and sets the path of the openCryptoFile to null.
	 *
	 * @param ciphertextPath The ciphertext file path to invalidate
	 */
	public void delete(Path ciphertextPath) {
		openCryptoFiles.compute(normalize(ciphertextPath), (p, openFile) -> {
			if (openFile != null) {
				openFile.updateCurrentFilePath(null);
			}
			return null;
		});
	}

	/**
	 * Runs an operation that replaces the given file, e.g. by copying another file onto it.
	 * While the operation runs, {@link #open(Path, SupplierThrowingException) opening} this file waits.
	 * Once the operation succeeded, any OpenCryptoFile of this file gets detached like a {@link #delete(Path) deleted} file: Its channels keep working, but nothing gets persisted to this file anymore.
	 *
	 * @param ciphertextPath Path of the file to replace
	 * @param operation The operation that replaces the file
	 * @throws IOException If the operation failed
	 */
	public void replace(Path ciphertextPath, RunnableThrowingException<IOException> operation) throws IOException {
		Runnable unlock = lockPaths(List.of(ciphertextPath), lock -> lock.writeLock());
		try {
			operation.run();
			delete(ciphertextPath);
		} finally {
			unlock.run();
		}
	}

	/**
	 * Prepares to update any open file references during a move operation.
	 * MUST be invoked using a try-with-resource statement and committed after the physical file move succeeded.
	 * Until the returned TwoPhaseMove is closed, {@link #open(Path, SupplierThrowingException) opening} any of the given paths waits, so that no channel gets opened while the physical file move is in progress.
	 * <p>
	 * On commit, any OpenCryptoFile of <code>dst</code> or <code>replacedPaths</code> gets detached like a {@link #delete(Path) deleted} file: Its channels keep working, but nothing gets persisted to the destination anymore.
	 *
	 * @param src The ciphertext file path before the move
	 * @param dst The ciphertext file path after the move
	 * @param cleartextDst cleartext file path after the move
	 * @param replaceExisting whether the destination file may be currently opened
	 * @param replacedPaths further ciphertext paths of a destination node that the move replaces, e.g. the file path of a file replaced by a symlink
	 * @return Utility to update OpenCryptoFile references.
	 * @throws FileAlreadyExistsException Thrown if the destination file is an existing file that is currently opened and <code>replaceExisting</code> is not set.
	 */
	public TwoPhaseMove prepareMove(Path src, Path dst, CryptoPath cleartextDst, boolean replaceExisting, Path... replacedPaths) throws FileAlreadyExistsException {
		return new TwoPhaseMove(src, dst, cleartextDst, replaceExisting, List.of(replacedPaths));
	}

	/**
	 * Close all currently opened files by invoking {@link OpenCryptoFile#close()}.
	 */
	@Override
	public void close() {
		Iterator<Map.Entry<Path, OpenCryptoFile>> iter = openCryptoFiles.entrySet().iterator();
		while (iter.hasNext()) {
			Map.Entry<Path, OpenCryptoFile> entry = iter.next();
			iter.remove(); // remove before invoking close() to avoid concurrent modification of this iterator by #close(OpenCryptoFile)
			entry.getValue().close();
		}
	}

	/**
	 * Locks the given paths in a fixed order, which avoids deadlocks between concurrent callers.
	 *
	 * @param paths The paths to lock
	 * @param lockType Selects the read or write lock
	 * @return An action that unlocks the paths
	 */
	private Runnable lockPaths(Collection<Path> paths, Function<ReentrantReadWriteLock, Lock> lockType) {
		List<Path> sortedPaths = paths.stream().map(OpenCryptoFiles::normalize).distinct().sorted().toList();
		List<Lock> locks = sortedPaths.stream().map(p -> lockType.apply(retainPathLock(p).lock)).toList(); // retain all before waiting for any, so no lock gets discarded while it is awaited
		locks.forEach(Lock::lock);
		return () -> {
			locks.reversed().forEach(Lock::unlock);
			sortedPaths.forEach(this::releasePathLock);
		};
	}

	private static Path normalize(Path ciphertextPath) {
		return ciphertextPath.toAbsolutePath().normalize();
	}

	private PathLock retainPathLock(Path normalizedPath) {
		return pathLocks.compute(normalizedPath, (p, pathLock) -> {
			PathLock result = pathLock == null ? new PathLock() : pathLock;
			result.users++;
			return result;
		});
	}

	private void releasePathLock(Path normalizedPath) {
		pathLocks.computeIfPresent(normalizedPath, (p, pathLock) -> --pathLock.users == 0 ? null : pathLock);
	}

	private static class PathLock {

		private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
		private int users; // only modified within ConcurrentMap#compute of pathLocks

	}

	public class TwoPhaseMove implements AutoCloseable {

		private final Path src;
		private final Path dst;
		private final CryptoPath cleartextDst;
		private final List<Path> replacedPaths;
		private final Runnable unlock;
		private boolean committed;
		private boolean rolledBack;

		private TwoPhaseMove(Path src, Path dst, CryptoPath cleartextDst, boolean replaceExisting, List<Path> replacedPaths) throws FileAlreadyExistsException {
			this.src = normalize(src);
			this.dst = normalize(dst);
			this.cleartextDst = cleartextDst;
			this.replacedPaths = replacedPaths;
			this.unlock = lockPaths(Stream.concat(Stream.of(this.src, this.dst), replacedPaths.stream()).toList(), lock -> lock.writeLock());
			if (!replaceExisting && openCryptoFiles.containsKey(this.dst)) {
				unlock.run();
				throw new FileAlreadyExistsException(this.dst.toString(), null, "Destination file currently accessed by another thread.");
			}
		}

		/**
		 * Remaps the OpenCryptoFile of the source to the destination, if it is still open, and detaches any replaced OpenCryptoFile.
		 * MUST be invoked after the physical file move succeeded.
		 */
		public void commit() {
			if (rolledBack) {
				throw new IllegalStateException();
			}
			OpenCryptoFile openCryptoFile = openCryptoFiles.get(src);
			if (openCryptoFile == null) {
				remap(null);
			} else {
				synchronized (openCryptoFile) { // the last channel unregisters the file under this monitor, so recheck to not map a closed file at dst
					remap(openCryptoFiles.get(src) == openCryptoFile ? openCryptoFile : null);
				}
			}
			committed = true;
		}

		private void remap(OpenCryptoFile openCryptoFile) {
			replacedPaths.forEach(OpenCryptoFiles.this::delete);
			openCryptoFiles.compute(dst, (k, replaced) -> {
				if (replaced != null && replaced != openCryptoFile) {
					// detach first, otherwise closing the replaced file's use token would delete the in-use file the source just moved onto
					replaced.updateCurrentFilePath(null);
				}
				if (openCryptoFile != null) {
					openCryptoFile.updateCurrentFilePath(dst);
					openCryptoFile.updateCurrentCleartextPath(cleartextDst);
				}
				return openCryptoFile;
			});
			openCryptoFiles.remove(src, openCryptoFile);
		}

		public void rollback() {
			if (committed) {
				throw new IllegalStateException();
			}
			rolledBack = true;
		}

		@Override
		public void close() {
			if (!committed) {
				rollback();
			}
			unlock.run();
		}
	}

}
