/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.Symlinks;
import org.cryptomator.cryptofs.common.ArrayUtils;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;

import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttributeView;
import java.util.Optional;

abstract sealed class AbstractCryptoFileAttributeView implements FileAttributeView
		permits CryptoBasicFileAttributeView, CryptoFileOwnerAttributeView {

	protected final CryptoPath cleartextPath;
	private final CryptoPathMapper pathMapper;
	protected final LinkOption[] linkOptions;
	private final Symlinks symlinks;
	private final OpenCryptoFiles openCryptoFiles;

	protected AbstractCryptoFileAttributeView(CryptoPath cleartextPath, CryptoPathMapper pathMapper, LinkOption[] linkOptions, Symlinks symlinks, OpenCryptoFiles openCryptoFiles) {
		this.cleartextPath = cleartextPath;
		this.pathMapper = pathMapper;
		this.linkOptions = linkOptions;
		this.symlinks = symlinks;
		this.openCryptoFiles = openCryptoFiles;
	}

	protected <T extends FileAttributeView> T getCiphertextAttributeView(Class<T> delegateType) throws IOException {
		Path ciphertextPath = getCiphertextPath(cleartextPath);
		return ciphertextPath.getFileSystem().provider().getFileAttributeView(ciphertextPath, delegateType);
	}

	protected Optional<OpenCryptoFile> getOpenCryptoFile() throws IOException {
		Path ciphertextPath = getCiphertextPath(cleartextPath);
		return openCryptoFiles.get(ciphertextPath);
	}

	private Path getCiphertextPath(CryptoPath path) throws IOException {
		CiphertextFileType type = pathMapper.getCiphertextFileType(path);
		return switch (type) {
			case SYMLINK:
				if (ArrayUtils.contains(linkOptions, LinkOption.NOFOLLOW_LINKS)) {
					yield pathMapper.getCiphertextFilePath(path).getSymlinkFilePath();
				} else {
					CryptoPath resolved = symlinks.resolveRecursively(path);
					yield getCiphertextPath(resolved);
				}
			case DIRECTORY:
				yield pathMapper.getCiphertextDir(path).path();
			case FILE:
				yield pathMapper.getCiphertextFilePath(path).getFilePath();
		};
	}

}
