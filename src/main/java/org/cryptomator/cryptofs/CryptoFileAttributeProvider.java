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
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.HashMap;
import java.util.Map;

import org.cryptomator.cryptolib.FileHeaderCryptor;

class CryptoFileAttributeProvider {

	private final Map<Class<? extends BasicFileAttributes>, AttributeProvider<? extends BasicFileAttributes>> attributeProviders = new HashMap<>();
	private final FileHeaderCryptor headerCryptor;

	public CryptoFileAttributeProvider(FileHeaderCryptor headerCryptor) {
		attributeProviders.put(BasicFileAttributes.class, (AttributeProvider<BasicFileAttributes>) CryptoBasicFileAttributes::new);
		attributeProviders.put(PosixFileAttributes.class, (AttributeProvider<PosixFileAttributes>) CryptoPosixFileAttributes::new);
		attributeProviders.put(DosFileAttributes.class, (AttributeProvider<DosFileAttributes>) CryptoDosFileAttributes::new);
		this.headerCryptor = headerCryptor;
	}

	@SuppressWarnings("unchecked")
	public <A extends BasicFileAttributes> A readAttributes(Path ciphertextPath, Class<A> type) throws IOException {
		if (attributeProviders.containsKey(type)) {
			A ciphertextAttrs = ciphertextPath.getFileSystem().provider().readAttributes(ciphertextPath, type);
			AttributeProvider<A> provider = (AttributeProvider<A>) attributeProviders.get(type);
			return provider.provide(ciphertextAttrs, ciphertextPath, headerCryptor);
		} else {
			throw new UnsupportedOperationException("Unsupported file attribute type: " + type);
		}
	}

	private static interface AttributeProvider<A extends BasicFileAttributes> {
		A provide(A delegate, Path ciphertextPath, FileHeaderCryptor headerCryptor);
	}

}
