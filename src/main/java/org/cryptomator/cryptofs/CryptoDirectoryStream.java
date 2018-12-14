/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.cryptomator.cryptofs.Constants.SHORT_NAMES_MAX_LENGTH;

class CryptoDirectoryStream implements DirectoryStream<Path> {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoDirectoryStream.class);

	private final String directoryId;
	private final DirectoryStream<Path> ciphertextDirStream;
	private final Path cleartextDir;
	private final FileNameCryptor filenameCryptor;
	private final CryptoPathMapper cryptoPathMapper;
	private final LongFileNameProvider longFileNameProvider;
	private final ConflictResolver conflictResolver;
	private final DirectoryStream.Filter<? super Path> filter;
	private final Consumer<CryptoDirectoryStream> onClose;
	private final FinallyUtil finallyUtil;
	private final EncryptedNamePattern encryptedNamePattern;

	public CryptoDirectoryStream(CiphertextDirectory ciphertextDir, Path cleartextDir, FileNameCryptor filenameCryptor, CryptoPathMapper cryptoPathMapper, LongFileNameProvider longFileNameProvider,
								 ConflictResolver conflictResolver, DirectoryStream.Filter<? super Path> filter, Consumer<CryptoDirectoryStream> onClose, FinallyUtil finallyUtil, EncryptedNamePattern encryptedNamePattern)
			throws IOException {
		this.onClose = onClose;
		this.finallyUtil = finallyUtil;
		this.encryptedNamePattern = encryptedNamePattern;
		this.directoryId = ciphertextDir.dirId;
		this.ciphertextDirStream = Files.newDirectoryStream(ciphertextDir.path);
		LOG.trace("OPEN {}", directoryId);
		this.cleartextDir = cleartextDir;
		this.filenameCryptor = filenameCryptor;
		this.cryptoPathMapper = cryptoPathMapper;
		this.longFileNameProvider = longFileNameProvider;
		this.conflictResolver = conflictResolver;
		this.filter = filter;
	}

	@Override
	public Iterator<Path> iterator() {
		return cleartextDirectoryListing().iterator();
	}

	private Stream<Path> cleartextDirectoryListing() {
		return directoryListing() //
				.map(ProcessedPaths::getCleartextPath) //
				.filter(this::isAcceptableByFilter);
	}

	public Stream<Path> ciphertextDirectoryListing() {
		return directoryListing().map(ProcessedPaths::getCiphertextPath);
	}

	private Stream<ProcessedPaths> directoryListing() {
		Stream<ProcessedPaths> pathIter = StreamSupport.stream(ciphertextDirStream.spliterator(), false).map(ProcessedPaths::new);
		Stream<ProcessedPaths> resolved = pathIter.map(this::resolveConflictingFileIfNeeded).filter(Objects::nonNull);
		Stream<ProcessedPaths> inflated = resolved.map(this::inflateIfNeeded).filter(Objects::nonNull);
		Stream<ProcessedPaths> decrypted = inflated.map(this::decrypt).filter(Objects::nonNull);
		Stream<ProcessedPaths> sanitized = decrypted.filter(this::passesPlausibilityChecks);
		return sanitized;
	}

	private ProcessedPaths resolveConflictingFileIfNeeded(ProcessedPaths paths) {
		try {
			return paths.withCiphertextPath(conflictResolver.resolveConflictsIfNecessary(paths.getCiphertextPath(), directoryId));
		} catch (IOException e) {
			LOG.warn("I/O exception while finding potentially conflicting file versions for {}.", paths.getCiphertextPath());
			return null;
		}
	}

	ProcessedPaths inflateIfNeeded(ProcessedPaths paths) {
		String fileName = paths.getCiphertextPath().getFileName().toString();
		if (longFileNameProvider.isDeflated(fileName)) {
			try {
				String longFileName = longFileNameProvider.inflate(fileName);
				if (longFileName.length() <= SHORT_NAMES_MAX_LENGTH) {
					// "unshortify" filenames on the fly due to previously shorter threshold
					return inflatePermanently(paths, longFileName);
				} else {
					return paths.withInflatedPath(paths.getCiphertextPath().resolveSibling(longFileName));
				}
			} catch (IOException e) {
				LOG.warn(paths.getCiphertextPath() + " could not be inflated.");
				return null;
			}
		} else {
			return paths.withInflatedPath(paths.getCiphertextPath());
		}
	}

	private ProcessedPaths decrypt(ProcessedPaths paths) {
		Optional<String> ciphertextName = encryptedNamePattern.extractEncryptedNameFromStart(paths.getInflatedPath());
		if (ciphertextName.isPresent()) {
			String ciphertext = ciphertextName.get();
			try {
				String cleartext = filenameCryptor.decryptFilename(ciphertext, directoryId.getBytes(StandardCharsets.UTF_8));
				return paths.withCleartextPath(cleartextDir.resolve(cleartext));
			} catch (AuthenticationFailedException e) {
				LOG.warn(paths.getInflatedPath() + " not decryptable due to an unauthentic ciphertext.");
				return null;
			}
		} else {
			return null;
		}
	}

	/**
	 * Checks if a given file belongs into this ciphertext dir.
	 * 
	 * @param paths The path to check.
	 * @return <code>true</code> if the file is an existing ciphertext or directory file.
	 */
	private boolean passesPlausibilityChecks(ProcessedPaths paths) {
		return !isBrokenDirectoryFile(paths);
	}

	private ProcessedPaths inflatePermanently(ProcessedPaths paths, String longFileName) throws IOException {
		Path newCiphertextPath = paths.getCiphertextPath().resolveSibling(longFileName);
		Files.move(paths.getCiphertextPath(), newCiphertextPath);
		return paths.withCiphertextPath(newCiphertextPath).withInflatedPath(newCiphertextPath);
	}

	private boolean isBrokenDirectoryFile(ProcessedPaths paths) {
		Path potentialDirectoryFile = paths.getCiphertextPath();
		if (paths.getInflatedPath().getFileName().toString().startsWith(Constants.DIR_PREFIX)) {
			final Path dirPath;
			try {
				dirPath = cryptoPathMapper.resolveDirectory(potentialDirectoryFile).path;
			} catch (IOException e) {
				LOG.warn("Broken directory file {}. Exception: {}", potentialDirectoryFile, e.getMessage());
				return true;
			}
			if (!Files.isDirectory(dirPath)) {
				LOG.warn("Broken directory file {}. Directory {} does not exist.", potentialDirectoryFile, dirPath);
				return true;
			}
		}
		return false;
	}

	private boolean isAcceptableByFilter(Path path) {
		try {
			return filter.accept(path);
		} catch (IOException e) {
			// as defined by DirectoryStream's contract:
			// > If an I/O error is encountered when accessing the directory then it
			// > causes the {@code Iterator}'s {@code hasNext} or {@code next} methods to
			// > throw {@link DirectoryIteratorException} with the {@link IOException} as the
			// > cause.
			throw new DirectoryIteratorException(e);
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	public void close() throws IOException {
		finallyUtil.guaranteeInvocationOf( //
				() -> ciphertextDirStream.close(), //
				() -> onClose.accept(this), //
				() -> LOG.trace("CLOSE {}", directoryId));
	}

	static class ProcessedPaths {

		private final Path ciphertextPath;
		private final Path inflatedPath;
		private final Path cleartextPath;

		public ProcessedPaths(Path ciphertextPath) {
			this(ciphertextPath, null, null);
		}

		private ProcessedPaths(Path ciphertextPath, Path inflatedPath, Path cleartextPath) {
			this.ciphertextPath = ciphertextPath;
			this.inflatedPath = inflatedPath;
			this.cleartextPath = cleartextPath;
		}

		public Path getCiphertextPath() {
			return ciphertextPath;
		}

		public Path getInflatedPath() {
			return inflatedPath;
		}

		public Path getCleartextPath() {
			return cleartextPath;
		}

		public ProcessedPaths withCiphertextPath(Path ciphertextPath) {
			return new ProcessedPaths(ciphertextPath, inflatedPath, cleartextPath);
		}

		public ProcessedPaths withInflatedPath(Path inflatedPath) {
			return new ProcessedPaths(ciphertextPath, inflatedPath, cleartextPath);
		}

		public ProcessedPaths withCleartextPath(Path cleartextPath) {
			return new ProcessedPaths(ciphertextPath, inflatedPath, cleartextPath);
		}

	}

}
