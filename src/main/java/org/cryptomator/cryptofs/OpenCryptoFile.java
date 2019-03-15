/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.ch.ChannelComponent;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;
import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLockInterruptionException;
import java.nio.channels.InterruptedByTimeoutException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

@PerOpenFile
class OpenCryptoFile implements Closeable {

	private static final int LOCK_TIMEOUT_MS = 100;

	private final OpenCryptoFiles openCryptoFiles;
	private final ReentrantReadWriteLock lock;
	private final AtomicReference<Instant> lastModified;
	private final AtomicReference<Path> currentFilePath;
	private final AtomicLong fileSize;
	private final OpenCryptoFileComponent component;
	private final ConcurrentMap<CleartextFileChannel, Boolean> openChannels = new ConcurrentHashMap<>();

	@Inject
	public OpenCryptoFile(OpenCryptoFiles openCryptoFiles, Supplier<BasicFileAttributeView> attrViewProvider, @CurrentOpenFilePath AtomicReference<Path> currentFilePath, @OpenFileSize AtomicLong fileSize, @OpenFileModifiedDate AtomicReference<Instant> lastModified, OpenCryptoFileComponent component) {
		this.lock = new ReentrantReadWriteLock();
		this.openCryptoFiles = openCryptoFiles;
		this.currentFilePath = currentFilePath;
		this.fileSize = fileSize;
		this.component = component;
		this.lastModified = lastModified;
	}

	public FileChannel newFileChannel(EffectiveOpenOptions options) throws IOException {
		Lock lock = getLock(options);
		boolean success = false;
		try {
			Path path = currentFilePath.get();
			FileChannel ciphertextFileChannel = path.getFileSystem().provider().newFileChannel(path, options.createOpenOptionsForEncryptedFile());
			ChannelComponent channelComponent = component.newChannelComponent() //
					.ciphertextChannel(ciphertextFileChannel) //
					.openOptions(options) //
					.lock(lock) //
					.onClose(this::channelClosed) //
					.build();
			success = true;
			CleartextFileChannel cleartextFileChannel = channelComponent.channel();
			openChannels.put(cleartextFileChannel, Boolean.TRUE);
			return cleartextFileChannel;
		} finally {
			if (!success) {
				lock.unlock();
			}
		}
	}

	private Lock getLock(EffectiveOpenOptions options) throws FileLockInterruptionException, InterruptedByTimeoutException {
		final Lock l;
		if (options.writable()) {
			l = lock.writeLock();
		} else {
			assert options.readable();
			l = lock.readLock();
		}
		try {
			if (!l.tryLock(LOCK_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
				throw new InterruptedByTimeoutException();
			} else {
				return l;
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new FileLockInterruptionException();
		}
	}

	public long size() {
		return fileSize.get();
	}

	public FileTime getLastModifiedTime() {
		return FileTime.from(lastModified.get());
	}

	public void setLastModifiedTime(FileTime lastModifiedTime) {
		lastModified.set(lastModifiedTime.toInstant());
	}

	public Path getCurrentFilePath() {
		return currentFilePath.get();
	}

	public void setCurrentFilePath(Path currentFilePath) {
		this.currentFilePath.set(currentFilePath);
	}

	private synchronized void channelClosed(CleartextFileChannel channel) {
		openChannels.remove(channel);
		if (openChannels.isEmpty()) {
			close();
		}
	}

	public void close() {
		openCryptoFiles.close(this);
	}

	@Override
	public String toString() {
		return "OpenCryptoFile(path=" + currentFilePath.toString() + ")";
	}
}
