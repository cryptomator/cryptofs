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
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;

import org.cryptomator.cryptolib.api.FileHeaderCryptor;

public class CryptoBasicFileAttributes implements DelegatingBasicFileAttributes {

	private final BasicFileAttributes delegate;
	protected final Path ciphertextPath;
	private final FileHeaderCryptor headerCryptor;
	private long size = -1;

	public CryptoBasicFileAttributes(BasicFileAttributes delegate, Path ciphertextPath, FileHeaderCryptor headerCryptor) {
		this.delegate = delegate;
		this.ciphertextPath = ciphertextPath;
		this.headerCryptor = headerCryptor;
	}

	@Override
	public BasicFileAttributes getDelegate() {
		return delegate;
	}

	@Override
	public boolean isRegularFile() {
		return getDelegate().isRegularFile() && !isDirectory();
	}

	@Override
	public boolean isDirectory() {
		return getDelegate().isRegularFile() && ciphertextPath.getFileName().toString().startsWith(Constants.DIR_PREFIX);
	}

	@Override
	public boolean isOther() {
		return false;
	}

	@Override
	public boolean isSymbolicLink() {
		return false;
	}

	@Override
	public long size() {
		if (isRegularFile() && getDelegate().size() >= headerCryptor.headerSize() && size == -1) {
			size = readSizeFromHeader();
		}
		return size;
	}

	private long readSizeFromHeader() {
		try {
			ByteBuffer buf = ByteBuffer.allocate(headerCryptor.headerSize());
			try (ReadableByteChannel r = ciphertextPath.getFileSystem().provider().newByteChannel(ciphertextPath, Collections.singleton(StandardOpenOption.READ))) {
				r.read(buf);
			}
			buf.flip();
			return headerCryptor.decryptHeader(buf).getFilesize();
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

}
