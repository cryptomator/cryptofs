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

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Optional;

@CryptoFileSystemScoped
public class AttributeProvider {

	private final AttributeComponent.Builder attributeComponentBuilder;
	private final CryptoPathMapper pathMapper;
	private final Symlinks symlinks;

	@Inject
	AttributeProvider(AttributeComponent.Builder attributeComponentBuilder, CryptoPathMapper pathMapper, Symlinks symlinks) {
		this.attributeComponentBuilder = attributeComponentBuilder;
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
		Optional<BasicFileAttributes> cleartextAttrs = attributeComponentBuilder  //
				.type(type) //
				.ciphertextFileType(ciphertextFileType) //
				.ciphertextPath(ciphertextPath) //
				.ciphertextAttributes(ciphertextAttrs) //
				.build() //
				.attributes();
		if (cleartextAttrs.isPresent() && type.isInstance(cleartextAttrs.get())) {
			return type.cast(cleartextAttrs.get());
		} else {
			throw new UnsupportedOperationException("Unsupported file attribute type: " + type);
		}
	}

	private Path getCiphertextPath(CryptoPath path, CiphertextFileType type) throws IOException {
		switch (type) {
			case SYMLINK:
				return pathMapper.getCiphertextFilePath(path).getSymlinkFilePath();
			case DIRECTORY:
				return pathMapper.getCiphertextDir(path).path;
			case FILE:
				return pathMapper.getCiphertextFilePath(path).getFilePath();
			default:
				throw new UnsupportedOperationException("Unhandled node type " + type);
		}
	}

}
