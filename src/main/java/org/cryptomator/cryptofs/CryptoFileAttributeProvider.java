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
import java.nio.file.FileSystemLoopException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.inject.Inject;

import org.cryptomator.cryptolib.api.Cryptor;

import static org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType.DIRECTORY;

@PerFileSystem
class CryptoFileAttributeProvider {

	private final Map<Class<? extends BasicFileAttributes>, AttributeProvider<? extends BasicFileAttributes>> attributeProviders = new HashMap<>();
	private final Cryptor cryptor;
	private final CryptoPathMapper pathMapper;
	private final OpenCryptoFiles openCryptoFiles;
	private final CryptoFileSystemProperties fileSystemProperties;
	private final Symlinks symlinks;

	@Inject
	public CryptoFileAttributeProvider(Cryptor cryptor, CryptoPathMapper pathMapper, OpenCryptoFiles openCryptoFiles, CryptoFileSystemProperties fileSystemProperties, Symlinks symlinks) {
		this.cryptor = cryptor;
		this.pathMapper = pathMapper;
		this.openCryptoFiles = openCryptoFiles;
		this.fileSystemProperties = fileSystemProperties;
		this.symlinks = symlinks;
		attributeProviders.put(BasicFileAttributes.class, (AttributeProvider<BasicFileAttributes>) CryptoBasicFileAttributes::new);
		attributeProviders.put(PosixFileAttributes.class, (AttributeProvider<PosixFileAttributes>) CryptoPosixFileAttributes::new);
		attributeProviders.put(DosFileAttributes.class, (AttributeProvider<DosFileAttributes>) CryptoDosFileAttributes::new);
	}

	public <A extends BasicFileAttributes> A readAttributes(CryptoPath cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		if (attributeProviders.containsKey(type)) {
			return readAttributes(new HashSet<>(), cleartextPath, type, options);
		} else {
			throw new UnsupportedOperationException("Unsupported file attribute type: " + type);
		}
	}

	private <A extends BasicFileAttributes> A readAttributes(Set<CryptoPath> visitedLinks, CryptoPath cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		CryptoPathMapper.CiphertextFileType ciphertextFileType = pathMapper.getCiphertextFileType(cleartextPath);
		switch (ciphertextFileType) {
			case SYMLINK: {
				if (ArrayUtils.contains(options, LinkOption.NOFOLLOW_LINKS)) {
					Path ciphertextPath = pathMapper.getCiphertextFilePath(cleartextPath, ciphertextFileType);
					return readAttributes(ciphertextFileType, ciphertextPath, type);
				} else if (visitedLinks.contains(cleartextPath)) {
					throw new FileSystemLoopException(cleartextPath.toString());
				} else {
					visitedLinks.add(cleartextPath);
					return readAttributes(visitedLinks, symlinks.readSymbolicLink(cleartextPath), type, options);
				}
			}
			case DIRECTORY: {
				Path ciphertextPath = pathMapper.getCiphertextDirPath(cleartextPath);
				return readAttributes(ciphertextFileType, ciphertextPath, type);
			}
			case FILE: {
				Path ciphertextPath = pathMapper.getCiphertextFilePath(cleartextPath, ciphertextFileType);
				return readAttributes(ciphertextFileType, ciphertextPath, type);
			}
			default:
				throw new UnsupportedOperationException("Unhandled node type " + ciphertextFileType);
		}
	}

	private <A extends BasicFileAttributes> A readAttributes(CryptoPathMapper.CiphertextFileType ciphertextFileType, Path ciphertextPath, Class<A> type) throws IOException {
		assert attributeProviders.containsKey(type);
		A ciphertextAttrs = Files.readAttributes(ciphertextPath, type);
		AttributeProvider<A> provider = (AttributeProvider<A>) attributeProviders.get(type);
		return provider.provide(ciphertextAttrs, ciphertextFileType, ciphertextPath, cryptor, openCryptoFiles.get(ciphertextPath), fileSystemProperties.readonly());
	}

	@FunctionalInterface
	private interface AttributeProvider<A extends BasicFileAttributes> {
		A provide(A delegate, CryptoPathMapper.CiphertextFileType ciphertextFileType, Path ciphertextPath, Cryptor cryptor, Optional<OpenCryptoFile> openCryptoFile, boolean readonly);
	}

}
