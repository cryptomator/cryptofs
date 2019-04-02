/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.ch.ChannelComponent;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;

import javax.inject.Inject;
import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

@OpenFileScoped
public class OpenCryptoFile implements Closeable {

	private final FileCloseListener listener;
	private final AtomicReference<Instant> lastModified;
	private final ChunkIO chunkIO;
	private final FileHeaderHandler headerHandler;
	private final AtomicReference<Path> currentFilePath;
	private final AtomicLong fileSize;
	private final OpenCryptoFileComponent component;
	private final ConcurrentMap<CleartextFileChannel, FileChannel> openChannels = new ConcurrentHashMap<>();

	@Inject
	public OpenCryptoFile(FileCloseListener listener, ChunkIO chunkIO, FileHeaderHandler headerHandler, @CurrentOpenFilePath AtomicReference<Path> currentFilePath, @OpenFileSize AtomicLong fileSize, @OpenFileModifiedDate AtomicReference<Instant> lastModified, OpenCryptoFileComponent component) {
		this.listener = listener;
		this.chunkIO = chunkIO;
		this.headerHandler = headerHandler;
		this.currentFilePath = currentFilePath;
		this.fileSize = fileSize;
		this.component = component;
		this.lastModified = lastModified;
	}

	public synchronized FileChannel newFileChannel(EffectiveOpenOptions options) throws IOException {
		Path path = currentFilePath.get();

		FileChannel ciphertextFileChannel = null;
		CleartextFileChannel cleartextFileChannel = null;
		try {
			ciphertextFileChannel = path.getFileSystem().provider().newFileChannel(path, options.createOpenOptionsForEncryptedFile());
			ChannelComponent channelComponent = component.newChannelComponent() //
					.ciphertextChannel(ciphertextFileChannel) //
					.openOptions(options) //
					.onClose(this::channelClosed) //
					.build();
			cleartextFileChannel = channelComponent.channel();
		} finally {
			if (cleartextFileChannel == null && ciphertextFileChannel != null) {
				// something didn't work
				ciphertextFileChannel.close();
			}
		}
		assert cleartextFileChannel != null; // otherwise there would have been an exception
		openChannels.put(cleartextFileChannel, ciphertextFileChannel);
		chunkIO.registerChannel(ciphertextFileChannel, options.writable());
		return cleartextFileChannel;
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

	private synchronized void channelClosed(CleartextFileChannel cleartextFileChannel) throws IOException {
		try {
			FileChannel ciphertextFileChannel = openChannels.remove(cleartextFileChannel);
			if (ciphertextFileChannel != null) {
				headerHandler.persistIfNeeded();
				chunkIO.unregisterChannel(ciphertextFileChannel);
				ciphertextFileChannel.close();
			}
		} finally {
			if (openChannels.isEmpty()) {
				close();
			}
		}
	}

	@Override
	public void close() {
		listener.close(currentFilePath.get(), this);
	}

	@Override
	public String toString() {
		return "OpenCryptoFile(path=" + currentFilePath.toString() + ")";
	}
}
