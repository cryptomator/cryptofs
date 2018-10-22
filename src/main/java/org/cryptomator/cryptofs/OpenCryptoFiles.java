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
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;

import static org.cryptomator.cryptofs.OpenCryptoFileModule.openCryptoFileModule;
import static org.cryptomator.cryptofs.UncheckedThrows.allowUncheckedThrowsOf;

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
		OpenCryptoFile result = allowUncheckedThrowsOf(IOException.class).from(() -> {
			// ConcurrentHashMap.computeIfAbsent is atomic, "create" is called at most once:
			return openCryptoFiles.computeIfAbsent(normalizedPath, ignored -> create(normalizedPath, options));
		});
		assert result != null : "computeIfAbsent will not return null";
		return result;
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
		OpenCryptoFileModule module = openCryptoFileModule() //
				.withPath(normalizedPath) //
				.withOptions(options) //
				.onClose(() -> openCryptoFiles.remove(normalizedPath)) //
				.build();
		return component.newOpenCryptoFileComponent(module).openCryptoFile();
	}

	public class TwoPhaseMove implements AutoCloseable {

		private final Path src;
		private final Path dst;
		private final OpenCryptoFile openCryptoFile;
		private boolean committed;
		private boolean rolledBack;

		private TwoPhaseMove(Path src, Path dst) throws FileAlreadyExistsException {
			this.src = src;
			this.dst = dst;
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
