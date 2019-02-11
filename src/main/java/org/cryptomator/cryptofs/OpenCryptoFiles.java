/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;

@PerFileSystem
class OpenCryptoFiles {

	private final CryptoFileSystemComponent component;
	private final FinallyUtil finallyUtil;
	private final ConcurrentMap<Path, OpenCryptoFile> openCryptoFiles = new ConcurrentHashMap<>();

	@Inject
	public OpenCryptoFiles(CryptoFileSystemComponent component, FinallyUtil finallyUtil) {
		this.component = component;
		this.finallyUtil = finallyUtil;
	}

	public Optional<OpenCryptoFile> get(Path ciphertextPath) {
		Path normalizedPath = ciphertextPath.toAbsolutePath().normalize();
		return Optional.ofNullable(openCryptoFiles.get(normalizedPath));
	}

	public OpenCryptoFile getOrCreate(Path ciphertextPath, EffectiveOpenOptions options) throws IOException {
		Path normalizedPath = ciphertextPath.toAbsolutePath().normalize();
		try {
			// ConcurrentHashMap.computeIfAbsent is atomic, "create" is called at most once:
			return openCryptoFiles.computeIfAbsent(normalizedPath, ignored -> create(normalizedPath, options));
		} catch (UncheckedIOException e) {
			throw new IOException("Error opening file: " + normalizedPath, e);
		}
	}

	public void writeCiphertextFile(Path ciphertextPath, EffectiveOpenOptions openOptions, ByteBuffer contents) throws IOException {
		try (OpenCryptoFile f = getOrCreate(ciphertextPath, openOptions); FileChannel ch = f.newFileChannel(openOptions)) {
			ch.write(contents);
		}
	}

	public ByteBuffer readCiphertextFile(Path ciphertextPath, EffectiveOpenOptions openOptions, int maxBufferSize) throws BufferUnderflowException, IOException {
		try (OpenCryptoFile f = getOrCreate(ciphertextPath, openOptions); FileChannel ch = f.newFileChannel(openOptions)) {
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

	public void close() throws IOException {
		Stream<RunnableThrowingException<IOException>> closers = openCryptoFiles.values().stream().map(openCryptoFile -> openCryptoFile::close);
		finallyUtil.guaranteeInvocationOf(closers.iterator());
	}

	private OpenCryptoFile create(Path normalizedPath, EffectiveOpenOptions options) {
		OpenCryptoFileComponent openCryptoFileComponent = component.newOpenCryptoFileComponent()
				.path(normalizedPath)
				.openOptions(options)
				.build();
		return openCryptoFileComponent.openCryptoFile();
	}

	void close(OpenCryptoFile openCryptoFile) {
		openCryptoFiles.remove(openCryptoFile.getCurrentFilePath());
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
				openCryptoFile.setCurrentFilePath(dst);
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
