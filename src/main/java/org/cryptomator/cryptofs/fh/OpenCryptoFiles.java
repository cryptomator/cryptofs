/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptofs.EffectiveOpenOptions;

import jakarta.inject.Inject;
import java.io.Closeable;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@CryptoFileSystemScoped
public class OpenCryptoFiles implements Closeable {

	private final OpenCryptoFileComponent.Factory openCryptoFileComponentFactory;
	private final ConcurrentMap<Path, OpenCryptoFile> openCryptoFiles = new ConcurrentHashMap<>();

	@Inject
	OpenCryptoFiles(OpenCryptoFileComponent.Factory openCryptoFileComponentFactory) {
		this.openCryptoFileComponentFactory = openCryptoFileComponentFactory;
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
		Path normalizedPath = ciphertextPath.toAbsolutePath().normalize();
		return Optional.ofNullable(openCryptoFiles.get(normalizedPath));
	}

	/**
	 * Opens a file to {@link OpenCryptoFile#newFileChannel(EffectiveOpenOptions, java.nio.file.attribute.FileAttribute[]) retrieve a FileChannel}. If this file is already opened, a shared instance is returned.
	 * Getting the file channel should be the next invocation, since the {@link OpenFileScoped lifecycle} of the OpenFile strictly depends on the lifecycle of the channel.
	 *
	 * @param ciphertextPath Path of the file to open
	 * @return The opened file.
	 * @see #get(Path)
	 */
	public OpenCryptoFile getOrCreate(Path ciphertextPath) {
		Path normalizedPath = ciphertextPath.toAbsolutePath().normalize();
		return openCryptoFiles.computeIfAbsent(normalizedPath, p -> openCryptoFileComponentFactory.create(p, openCryptoFiles::remove).openCryptoFile()); // computeIfAbsent is atomic, "create" is called at most once
	}

	public void writeCiphertextFile(Path ciphertextPath, EffectiveOpenOptions openOptions, ByteBuffer contents) throws IOException {
		try (OpenCryptoFile f = getOrCreate(ciphertextPath); FileChannel ch = f.newFileChannel(openOptions)) {
			ch.write(contents);
		}
	}

	public ByteBuffer readCiphertextFile(Path ciphertextPath, EffectiveOpenOptions openOptions, int maxBufferSize) throws BufferUnderflowException, IOException {
		try (OpenCryptoFile f = getOrCreate(ciphertextPath); FileChannel ch = f.newFileChannel(openOptions)) {
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
		openCryptoFiles.compute(ciphertextPath, (p, openFile) -> {
			if (openFile != null) {
				openFile.updateCurrentFilePath(null);
			}
			return null;
		});
	}

	/**
	 * Prepares to update any open file references during a move operation.
	 * MUST be invoked using a try-with-resource statement and committed after the physical file move succeeded.
	 *
	 * @param src The ciphertext file path before the move
	 * @param dst The ciphertext file path after the move
	 * @return Utility to update OpenCryptoFile references.
	 * @throws FileAlreadyExistsException Thrown if the destination file is an existing file that is currently opened.
	 */
	public TwoPhaseMove prepareMove(Path src, Path dst) throws FileAlreadyExistsException {
		return new TwoPhaseMove(src, dst);
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

	public class TwoPhaseMove implements AutoCloseable {

		private final Path src;
		private final Path dst;
		private final OpenCryptoFile openCryptoFile;
		private boolean committed;
		private boolean rolledBack;

		private TwoPhaseMove(Path src, Path dst) throws FileAlreadyExistsException {
			this.src = Objects.requireNonNull(src);
			this.dst = Objects.requireNonNull(dst);
			try {
				// ConcurrentHashMap.compute is atomic:
				this.openCryptoFile = openCryptoFiles.compute(dst, (k, v) -> {
					if (v == null) {
						return openCryptoFiles.get(src);
					} else {
						throw new AlreadyMappedException();
					}
				});
			} catch (AlreadyMappedException e) {
				throw new FileAlreadyExistsException(dst.toString(), null, "Destination file currently accessed by another thread.");
			}
		}

		public void commit() {
			if (rolledBack) {
				throw new IllegalStateException();
			}
			if (openCryptoFile != null) {
				openCryptoFile.updateCurrentFilePath(dst);
			}
			openCryptoFiles.remove(src, openCryptoFile);
			committed = true;
		}

		public void rollback() {
			if (committed) {
				throw new IllegalStateException();
			}
			openCryptoFiles.remove(dst, openCryptoFile);
			rolledBack = true;
		}

		@Override
		public void close() {
			if (!committed) {
				rollback();
			}
		}
	}

	private static class AlreadyMappedException extends RuntimeException {

	}

}
