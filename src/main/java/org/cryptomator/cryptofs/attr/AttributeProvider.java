/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.ArrayUtils;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptofs.Symlinks;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@CryptoFileSystemScoped
public class AttributeProvider {

	private static final Map<Class<? extends BasicFileAttributes>, AttributesConstructor<? extends BasicFileAttributes>> ATTR_CONSTRUCTORS;

	static {
		ATTR_CONSTRUCTORS = new HashMap<>();
		ATTR_CONSTRUCTORS.put(BasicFileAttributes.class, (AttributesConstructor<BasicFileAttributes>) CryptoBasicFileAttributes::new);
		ATTR_CONSTRUCTORS.put(PosixFileAttributes.class, (AttributesConstructor<PosixFileAttributes>) CryptoPosixFileAttributes::new);
		ATTR_CONSTRUCTORS.put(DosFileAttributes.class, (AttributesConstructor<DosFileAttributes>) CryptoDosFileAttributes::new);
	}

	private final Cryptor cryptor;
	private final CryptoPathMapper pathMapper;
	private final OpenCryptoFiles openCryptoFiles;
	private final CryptoFileSystemProperties fileSystemProperties;
	private final Symlinks symlinks;

	@Inject
	AttributeProvider(Cryptor cryptor, CryptoPathMapper pathMapper, OpenCryptoFiles openCryptoFiles, CryptoFileSystemProperties fileSystemProperties, Symlinks symlinks) {
		this.cryptor = cryptor;
		this.pathMapper = pathMapper;
		this.openCryptoFiles = openCryptoFiles;
		this.fileSystemProperties = fileSystemProperties;
		this.symlinks = symlinks;
	}

	public <A extends BasicFileAttributes> A readAttributes(CryptoPath cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		if (!ATTR_CONSTRUCTORS.containsKey(type)) {
			throw new UnsupportedOperationException("Unsupported file attribute type: " + type);
		}
		CryptoPathMapper.CiphertextFileType ciphertextFileType = pathMapper.getCiphertextFileType(cleartextPath);
		switch (ciphertextFileType) {
			case SYMLINK: {
				if (ArrayUtils.contains(options, LinkOption.NOFOLLOW_LINKS)) {
					Path ciphertextPath = pathMapper.getCiphertextFilePath(cleartextPath, ciphertextFileType);
					return readAttributes(ciphertextFileType, ciphertextPath, type);
				} else {
					CryptoPath resolved = symlinks.resolveRecursively(cleartextPath);
					return readAttributes(resolved, type, options);
				}
			}
			case DIRECTORY: {
				Path ciphertextPath = pathMapper.getCiphertextDir(cleartextPath).path;
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
		assert ATTR_CONSTRUCTORS.containsKey(type);
		A ciphertextAttrs = Files.readAttributes(ciphertextPath, type);
		AttributesConstructor<A> constructor = (AttributesConstructor<A>) ATTR_CONSTRUCTORS.get(type);
		return constructor.construct(ciphertextAttrs, ciphertextFileType, ciphertextPath, cryptor, openCryptoFiles.get(ciphertextPath), fileSystemProperties.readonly());
	}

	@FunctionalInterface
	private interface AttributesConstructor<A extends BasicFileAttributes> {
		A construct(A delegate, CryptoPathMapper.CiphertextFileType ciphertextFileType, Path ciphertextPath, Cryptor cryptor, Optional<OpenCryptoFile> openCryptoFile, boolean readonlyFileSystem);
	}

}
