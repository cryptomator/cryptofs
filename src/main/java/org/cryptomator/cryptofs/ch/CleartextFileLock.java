/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.ch;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.Objects;

class CleartextFileLock extends FileLock {

	private final FileLock ciphertextLock;

	public CleartextFileLock(FileChannel channel, FileLock ciphertextLock, long position, long size) {
		super(Objects.requireNonNull(channel), position, size, ciphertextLock.isShared());
		this.ciphertextLock = Objects.requireNonNull(ciphertextLock);
	}

	FileLock delegate() {
		return ciphertextLock;
	}

	@Override
	public boolean isValid() {
		return ciphertextLock.isValid() && channel().isOpen();
	}

	@Override
	public void release() throws IOException {
		ciphertextLock.release();
	}

}
