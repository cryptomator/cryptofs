/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.dir;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.cryptomator.cryptofs.LongFileNameProvider;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
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

@DirectoryStreamScoped
public class CryptoDirectoryStream implements DirectoryStream<Path> {

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
	private final EncryptedNamePattern encryptedNamePattern;

	@Inject
	public CryptoDirectoryStream(CiphertextDirectory ciphertextDir, DirectoryStream<Path> ciphertextDirStream, @Named("cleartextPath") Path cleartextDir, Cryptor cryptor, CryptoPathMapper cryptoPathMapper, LongFileNameProvider longFileNameProvider,
								 ConflictResolver conflictResolver, DirectoryStream.Filter<? super Path> filter, Consumer<CryptoDirectoryStream> onClose, EncryptedNamePattern encryptedNamePattern) {
		this.onClose = onClose;
		this.encryptedNamePattern = encryptedNamePattern;
		this.directoryId = ciphertextDir.dirId;
		this.ciphertextDirStream = ciphertextDirStream;
		LOG.trace("OPEN {}", directoryId);
		this.cleartextDir = cleartextDir;
		this.filenameCryptor = cryptor.fileNameCryptor();
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
				String longFileName = longFileNameProvider.inflate(paths.getCiphertextPath());
				return paths.withInflatedPath(paths.getCiphertextPath().resolveSibling(longFileName));
			} catch (IOException e) {
				LOG.warn(paths.getCiphertextPath() + " could not be inflated.");
				return null;
			}
		} else {
			return paths.withInflatedPath(paths.getCiphertextPath());
		}
	}

	private ProcessedPaths decrypt(ProcessedPaths paths) {
		Optional<String> ciphertextName = encryptedNamePattern.extractEncryptedName(paths.getInflatedPath());
		if (ciphertextName.isPresent()) {
			String ciphertext = ciphertextName.get();
			try {
				String cleartext = filenameCryptor.decryptFilename(BaseEncoding.base64Url(), ciphertext, directoryId.getBytes(StandardCharsets.UTF_8));
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

	private boolean isBrokenDirectoryFile(ProcessedPaths paths) {
		Path potentialDirectoryFile = paths.getCiphertextPath().resolve(Constants.DIR_FILE_NAME);
		if (Files.isRegularFile(potentialDirectoryFile)) {
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
	public void close() throws IOException {
		try {
			ciphertextDirStream.close();
			LOG.trace("CLOSE {}", directoryId);
		} finally {
			onClose.accept(this);
		}
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
