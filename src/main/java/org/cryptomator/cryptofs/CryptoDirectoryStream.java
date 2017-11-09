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
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.cryptomator.cryptofs.CryptoPathMapper.Directory;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	public CryptoDirectoryStream(Directory ciphertextDir, Path cleartextDir, FileNameCryptor filenameCryptor, CryptoPathMapper cryptoPathMapper, LongFileNameProvider longFileNameProvider,
			ConflictResolver conflictResolver, DirectoryStream.Filter<? super Path> filter, Consumer<CryptoDirectoryStream> onClose, FinallyUtil finallyUtil, EncryptedNamePattern encryptedNamePattern)
			throws IOException {
		this.onClose = onClose;
		this.finallyUtil = finallyUtil;
		this.encryptedNamePattern = encryptedNamePattern;
		this.directoryId = ciphertextDir.dirId;
		this.ciphertextDirStream = Files.newDirectoryStream(ciphertextDir.path, p -> true);
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
		Stream<Path> pathIter = StreamSupport.stream(ciphertextDirStream.spliterator(), false);
		Stream<Path> resolved = pathIter.map(this::resolveConflictingFileIfNeeded).filter(Objects::nonNull);
		Stream<Path> sanitized = resolved.filter(this::passesPlausibilityChecks);
		Stream<Path> inflated = sanitized.map(this::inflateIfNeeded).filter(Objects::nonNull);
		Stream<Path> decrypted = inflated.map(this::decrypt).filter(Objects::nonNull);
		Stream<Path> filtered = decrypted.filter(this::isAcceptableByFilter);
		return filtered.iterator();
	}

	private Path resolveConflictingFileIfNeeded(Path potentiallyConflictingPath) {
		try {
			return conflictResolver.resolveConflictsIfNecessary(potentiallyConflictingPath, directoryId);
		} catch (IOException e) {
			LOG.warn("I/O exception while finding potentially conflicting file versions for {}.", potentiallyConflictingPath);
			return null;
		}
	}

	private Path inflateIfNeeded(Path ciphertextPath) {
		String fileName = ciphertextPath.getFileName().toString();
		if (LongFileNameProvider.isDeflated(fileName)) {
			try {
				String longFileName = longFileNameProvider.inflate(fileName);
				return ciphertextPath.resolveSibling(longFileName);
			} catch (IOException e) {
				LOG.warn(ciphertextPath + " could not be inflated.");
				return null;
			}
		} else {
			return ciphertextPath;
		}
	}

	/**
	 * Checks if a given file belongs into this ciphertext dir.
	 * 
	 * @param ciphertextPath The path to check.
	 * @return <code>true</code> if the file is an existing ciphertext or directory file.
	 */
	private boolean passesPlausibilityChecks(Path ciphertextPath) {
		return !isBrokenDirectoryFile(ciphertextPath);
	}

	private boolean isBrokenDirectoryFile(Path potentialDirectoryFile) {
		if (potentialDirectoryFile.getFileName().toString().startsWith(Constants.DIR_PREFIX)) {
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

	private Path decrypt(Path ciphertextPath) {
		Optional<String> encryptedName = encryptedNamePattern.extractEncryptedNameFromStart(ciphertextPath);
		if (encryptedName.isPresent()) {
			String ciphertext = encryptedName.get();
			try {
				String cleartext = filenameCryptor.decryptFilename(ciphertext, directoryId.getBytes(StandardCharsets.UTF_8));
				return cleartextDir.resolve(cleartext);
			} catch (AuthenticationFailedException e) {
				LOG.warn(ciphertextPath + " not decryptable due to an unauthentic ciphertext.");
				return null;
			}
		} else {
			return null;
		}
	}

	private boolean isAcceptableByFilter(Path path) {
		try {
			return filter.accept(path);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
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

}
