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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

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

	@Inject
	public CryptoFileAttributeProvider(Cryptor cryptor, CryptoPathMapper pathMapper, OpenCryptoFiles openCryptoFiles, CryptoFileSystemProperties fileSystemProperties) {
		this.cryptor = cryptor;
		this.pathMapper = pathMapper;
		this.openCryptoFiles = openCryptoFiles;
		this.fileSystemProperties = fileSystemProperties;
		attributeProviders.put(BasicFileAttributes.class, (AttributeProvider<BasicFileAttributes>) CryptoBasicFileAttributes::new);
		attributeProviders.put(PosixFileAttributes.class, (AttributeProvider<PosixFileAttributes>) CryptoPosixFileAttributes::new);
		attributeProviders.put(DosFileAttributes.class, (AttributeProvider<DosFileAttributes>) CryptoDosFileAttributes::new);
	}

	@SuppressWarnings("unchecked")
	public <A extends BasicFileAttributes> A readAttributes(CryptoPath cleartextPath, Class<A> type) throws IOException {
		if (attributeProviders.containsKey(type)) {
			CryptoPathMapper.CiphertextFileType ciphertextFileType = pathMapper.getCiphertextFileType(cleartextPath);
			Path ciphertextPath = DIRECTORY.equals(ciphertextFileType) //
					? pathMapper.getCiphertextDirPath(cleartextPath) //
					: pathMapper.getCiphertextFilePath(cleartextPath, ciphertextFileType);
			A ciphertextAttrs = Files.readAttributes(ciphertextPath, type);
			AttributeProvider<A> provider = (AttributeProvider<A>) attributeProviders.get(type);
			return provider.provide(ciphertextAttrs, ciphertextFileType, ciphertextPath, cryptor, openCryptoFiles.get(ciphertextPath), fileSystemProperties.readonly());
		} else {
			throw new UnsupportedOperationException("Unsupported file attribute type: " + type);
		}
	}

	@FunctionalInterface
	private interface AttributeProvider<A extends BasicFileAttributes> {
		A provide(A delegate, CryptoPathMapper.CiphertextFileType ciphertextFileType, Path ciphertextPath, Cryptor cryptor, Optional<OpenCryptoFile> openCryptoFile, boolean readonly);
	}

}
