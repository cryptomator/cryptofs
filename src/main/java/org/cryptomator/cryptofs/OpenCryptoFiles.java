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
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;

import static org.cryptomator.cryptofs.OpenCryptoFileModule.openCryptoFileModule;
import static org.cryptomator.cryptofs.UncheckedThrows.allowUncheckedThrowsOf;

@PerFileSystem
class OpenCryptoFiles {

	private final CryptoFileSystemComponent component;
	private final FinallyUtil finallyUtil;
	private final ConcurrentMap<Path, OpenCryptoFile> openCryptoFiles = new ConcurrentHashMap<>();
	private final Lock lock = new ReentrantLock();

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
			return openCryptoFiles.computeIfAbsent(normalizedPath, ignored -> create(normalizedPath, options));
		});
		assert result != null : "computeIfAbsent will not return null";
		return result;
	}

	/**
	 * Creates a utility allowing to update currently opened file references.
	 * MUST be used in a try-with-resource statement to avoid deadlocks.
	 * SHOULD be called before applying any changes to the underlying file system that might affect currently opened file handles.
	 *
	 * @return Utility to update OpenCryptoFile references.
	 */
	public OpenFileMove twoPhaseMove() {
		return new OpenFileMove();
	}

	public void close() throws IOException {
		lock.lock();
		try {
			Stream<RunnableThrowingException<IOException>> closers = openCryptoFiles.values().stream().map(openCryptoFile -> openCryptoFile::close);
			finallyUtil.guaranteeInvocationOf(closers.iterator());
		} finally {
			lock.unlock();
		}
	}

	private OpenCryptoFile create(Path normalizedPath, EffectiveOpenOptions options) {
		lock.lock();
		try {
			OpenCryptoFileModule module = openCryptoFileModule() //
					.withPath(normalizedPath) //
					.withOptions(options) //
					.onClose(() -> openCryptoFiles.remove(normalizedPath)) //
					.build();
			return component.newOpenCryptoFileComponent(module).openCryptoFile();
		} finally {
			lock.unlock();
		}
	}

	public class OpenFileMove implements AutoCloseable {

		private OpenFileMove() {
			lock.lock();
		}

		/**
		 * Updates references to an opened file (if any) from src to dst.
		 * Should be called after moving said file.
		 *
		 * @param src The old ciphertext path
		 * @param dst The new ciphertext path
		 * @throws FileAlreadyExistsException Thrown if another thread is already accessing dst.
		 */
		public void moveOpenedFile(Path src, Path dst) throws FileAlreadyExistsException {
			Path normalizedSrc = src.toAbsolutePath().normalize();
			Path normalizedDst = dst.toAbsolutePath().normalize();
			if (openCryptoFiles.get(normalizedDst) != null) {
				throw new FileAlreadyExistsException(normalizedDst.toString(), null, "Destination file already exists.");
			}
			openCryptoFiles.compute(normalizedDst, (k, v) -> {
				assert v == null; // we're exclusive lock owner and just checked that dst doesn't exist yet.
				return openCryptoFiles.get(normalizedSrc);
			});
		}

		@Override
		public void close() {
			lock.unlock();
		}
	}

}
