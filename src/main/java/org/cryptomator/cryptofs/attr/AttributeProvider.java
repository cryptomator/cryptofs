/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.Symlinks;
import org.cryptomator.cryptofs.common.ArrayUtils;
import org.cryptomator.cryptofs.common.CiphertextFileType;

import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

@CryptoFileSystemScoped
public class AttributeProvider {

	private final AttributeComponent.Factory attributeComponentFactory;
	private final CryptoPathMapper pathMapper;
	private final Symlinks symlinks;

	@Inject
	AttributeProvider(AttributeComponent.Factory attributeComponentFactory, CryptoPathMapper pathMapper, Symlinks symlinks) {
		this.attributeComponentFactory = attributeComponentFactory;
		this.pathMapper = pathMapper;
		this.symlinks = symlinks;
	}

	public <A extends BasicFileAttributes> A readAttributes(CryptoPath cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		CiphertextFileType ciphertextFileType = pathMapper.getCiphertextFileType(cleartextPath);
		if (ciphertextFileType == CiphertextFileType.SYMLINK && !ArrayUtils.contains(options, LinkOption.NOFOLLOW_LINKS)) {
			cleartextPath = symlinks.resolveRecursively(cleartextPath);
			ciphertextFileType = pathMapper.getCiphertextFileType(cleartextPath);
		}
		Path ciphertextPath = getCiphertextPath(cleartextPath, ciphertextFileType);
		A ciphertextAttrs = Files.readAttributes(ciphertextPath, type);
		return attributeComponentFactory.create(ciphertextPath, //
						ciphertextFileType, //
						ciphertextAttrs) //
				.attributes(type); //
	}

	private Path getCiphertextPath(CryptoPath path, CiphertextFileType type) throws IOException {
		return switch (type) {
			case SYMLINK -> pathMapper.getCiphertextFilePath(path).getSymlinkFilePath();
			case DIRECTORY -> pathMapper.getCiphertextDir(path).path();
			case FILE -> pathMapper.getCiphertextFilePath(path).getFilePath();
		};
	}

}
