/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.dir;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import java.io.IOException;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

@DirectoryStreamScoped
public class CryptoDirectoryStream implements DirectoryStream<Path> {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoDirectoryStream.class);

	private final String directoryId;
	private final DirectoryStream<Path> ciphertextDirStream;
	private final Path cleartextDir;
	private final DirectoryStream.Filter<? super Path> filter;
	private final Consumer<CryptoDirectoryStream> onClose;
	private final NodeProcessor nodeProcessor;

	@Inject
	public CryptoDirectoryStream(@Named("dirId") String dirId, DirectoryStream<Path> ciphertextDirStream, @Named("cleartextPath") Path cleartextDir, DirectoryStream.Filter<? super Path> filter, Consumer<CryptoDirectoryStream> onClose, NodeProcessor nodeProcessor) {
		LOG.trace("OPEN {}", dirId);
		this.directoryId = dirId;
		this.ciphertextDirStream = ciphertextDirStream;
		this.cleartextDir = cleartextDir;
		this.filter = filter;
		this.onClose = onClose;
		this.nodeProcessor = nodeProcessor;
	}

	@Override
	public Iterator<Path> iterator() {
		return cleartextDirectoryListing().iterator();
	}

	private Stream<Path> cleartextDirectoryListing() {
		return directoryListing()
				.map(node -> cleartextDir.resolve(node.cleartextName))
				.filter(this::isAcceptableByFilter);
	}

	Stream<Path> ciphertextDirectoryListing() {
		return directoryListing().map(node -> node.ciphertextPath);
	}

	private Stream<Node> directoryListing() {
		return StreamSupport.stream(ciphertextDirStream.spliterator(), false).map(Node::new).flatMap(nodeProcessor::process);
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

}
