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
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cryptomator.cryptofs.CryptoPathMapper.Directory;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Iterators;

class CryptoDirectoryStream implements DirectoryStream<Path> {

	private static final Pattern BASE32_PATTERN = Pattern.compile("^0?(([A-Z2-7]{8})*[A-Z2-7=]{8})");
	private static final Logger LOG = LoggerFactory.getLogger(CryptoDirectoryStream.class);

	private final String directoryId;
	private final DirectoryStream<Path> ciphertextDirStream;
	private final Path cleartextDir;
	private final FileNameCryptor filenameCryptor;
	private final LongFileNameProvider longFileNameProvider;
	private final DirectoryStream.Filter<? super Path> filter;

	public CryptoDirectoryStream(Directory ciphertextDir, Path cleartextDir, FileNameCryptor filenameCryptor, LongFileNameProvider longFileNameProvider, DirectoryStream.Filter<? super Path> filter) throws IOException {
		this.directoryId = ciphertextDir.dirId;
		this.ciphertextDirStream = ciphertextDir.path.getFileSystem().provider().newDirectoryStream(ciphertextDir.path, p -> true);
		this.cleartextDir = cleartextDir;
		this.filenameCryptor = filenameCryptor;
		this.longFileNameProvider = longFileNameProvider;
		this.filter = filter;
	}

	@Override
	public Iterator<Path> iterator() {
		Iterator<Path> ciphertextPathIter = ciphertextDirStream.iterator();
		Iterator<Path> longCiphertextPathOrNullIter = Iterators.transform(ciphertextPathIter, this::inflateIfNeeded);
		Iterator<Path> longCiphertextPathIter = Iterators.filter(longCiphertextPathOrNullIter, Objects::nonNull);
		Iterator<Path> cleartextPathOrNullIter = Iterators.transform(longCiphertextPathIter, this::decrypt);
		Iterator<Path> cleartextPathIter = Iterators.filter(cleartextPathOrNullIter, Objects::nonNull);
		return Iterators.filter(cleartextPathIter, this::isAcceptableByFilter);
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

	private Path decrypt(Path ciphertextPath) {
		String ciphertextFileName = ciphertextPath.getFileName().toString();
		Matcher m = BASE32_PATTERN.matcher(ciphertextFileName);
		if (m.find()) {
			String ciphertext = m.group(1);
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
	public void close() throws IOException {
		ciphertextDirStream.close();
	}

}
