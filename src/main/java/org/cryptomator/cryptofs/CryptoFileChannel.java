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
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

/**
 * Not thread-safe.
 */
class CryptoFileChannel extends AbstractFileChannel {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoFileChannel.class);
	private static final int MAX_CACHED_CLEARTEXT_CHUNKS = 5;

	private final Cryptor cryptor;
	private final FileChannel ch;
	private final FileHeader header;
	private final LoadingCache<Long, ByteBuffer> cleartextChunks;
	private final Set<OpenOption> openOptions;
	private final Collection<IOException> ioExceptionsDuringWrite = new ArrayList<>();

	public CryptoFileChannel(Cryptor cryptor, Path ciphertextPath, Set<? extends OpenOption> options) throws IOException {
		this.cryptor = cryptor;
		Set<OpenOption> adjustedOptions = new HashSet<>(options);
		adjustedOptions.remove(StandardOpenOption.APPEND);
		adjustedOptions.add(StandardOpenOption.READ);
		openOptions = Collections.unmodifiableSet(adjustedOptions);
		ch = FileChannel.open(ciphertextPath, adjustedOptions);
		if (adjustedOptions.contains(StandardOpenOption.CREATE_NEW) || adjustedOptions.contains(StandardOpenOption.CREATE) && ch.size() == 0) {
			header = cryptor.fileHeaderCryptor().create();
		} else {
			ByteBuffer existingHeaderBuf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
			ch.position(0);
			ch.read(existingHeaderBuf);
			existingHeaderBuf.flip();
			header = cryptor.fileHeaderCryptor().decryptHeader(existingHeaderBuf);
		}
		cleartextChunks = CacheBuilder.newBuilder().maximumSize(MAX_CACHED_CLEARTEXT_CHUNKS).removalListener(new CleartextChunkSaver()).build(new CleartextChunkLoader());
	}

	@Override
	public int read(ByteBuffer dst, long position) throws IOException {
		int origLimit = dst.limit();
		dst.limit((int) Math.min(origLimit, size() - position));
		int read = 0;
		int payloadSize = cryptor.fileContentCryptor().cleartextChunkSize();
		while (dst.hasRemaining()) {
			long pos = position + read;
			long chunkIndex = pos / payloadSize;
			int offset = (int) pos % payloadSize;
			int len = Math.min(dst.remaining(), payloadSize - offset);
			final ByteBuffer chunkBuf = loadCleartextChunk(chunkIndex);
			chunkBuf.position(offset).limit(Math.min(chunkBuf.limit(), len));
			dst.put(chunkBuf);
			read += len;
		}
		dst.limit(origLimit);
		return read;
	}

	@Override
	public int write(ByteBuffer src, long position) throws IOException {
		int written = 0;
		int payloadSize = cryptor.fileContentCryptor().cleartextChunkSize();
		while (src.hasRemaining()) {
			long pos = position + written;
			long chunkIndex = pos / payloadSize;
			int offset = (int) pos % payloadSize;
			int len = Math.min(src.remaining(), payloadSize - offset);
			if (pos + len > size()) {
				// append
				setSize(pos + len);
			}
			if (len == payloadSize) {
				// complete chunk, no need to load and decrypt from file:
				cleartextChunks.put(chunkIndex, ByteBuffer.allocate(payloadSize));
			}
			final ByteBuffer chunkBuf = loadCleartextChunk(chunkIndex);
			chunkBuf.position(offset).limit(Math.max(chunkBuf.limit(), len));
			int origLimit = src.limit();
			src.limit(src.position() + len);
			chunkBuf.put(src);
			src.limit(origLimit);
			written += len;
		}
		return written;
	}

	@Override
	public long size() {
		return header.getFilesize();
	}

	private void setSize(long size) {
		header.setFilesize(size);
	}

	@Override
	public FileChannel truncate(long size) throws IOException {
		ch.truncate(cryptor.fileHeaderCryptor().headerSize());
		setSize(Math.min(size, size()));
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void force(boolean metaData) throws IOException {
		cleartextChunks.invalidateAll();
		if (openOptions.contains(StandardOpenOption.WRITE)) {
			ch.write(cryptor.fileHeaderCryptor().encryptHeader(header), 0);
		}
		ch.force(metaData);
	}

	@Override
	public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public FileLock lock(long position, long size, boolean shared) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public FileLock tryLock(long position, long size, boolean shared) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void implCloseChannel() throws IOException {
		try {
			// TODO append size obfuscation padding?
			force(true);
			if (!ioExceptionsDuringWrite.isEmpty()) {
				throw new IOException("Failed to write at least " + ioExceptionsDuringWrite.size() + " chunk(s).");
			}
		} catch (IOException e) {
			ioExceptionsDuringWrite.forEach(e::addSuppressed);
			throw e;
		} finally {
			ch.close();
		}
	}

	private ByteBuffer loadCleartextChunk(long chunkIndex) {
		try {
			return cleartextChunks.get(chunkIndex);
		} catch (ExecutionException e) {
			if (e.getCause() instanceof AuthenticationFailedException) {
				// TODO
				throw new UnsupportedOperationException("TODO", e);
			} else {
				throw new IllegalStateException("Unexpected Exception.", e);
			}
		}
	}

	private class CleartextChunkLoader extends CacheLoader<Long, ByteBuffer> {

		@Override
		public ByteBuffer load(Long chunkIndex) throws Exception {
			LOG.debug("load chunk" + chunkIndex);
			int payloadSize = cryptor.fileContentCryptor().cleartextChunkSize();
			int chunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
			long ciphertextPos = chunkIndex * chunkSize + cryptor.fileHeaderCryptor().headerSize();
			ByteBuffer ciphertextBuf = ByteBuffer.allocate(chunkSize);
			int read = ch.read(ciphertextBuf, ciphertextPos);
			if (read == -1) {
				// append
				return ByteBuffer.allocate(payloadSize);
			} else {
				ciphertextBuf.flip();
				return cryptor.fileContentCryptor().decryptChunk(ciphertextBuf, chunkIndex, header, true);
			}
		}

	}

	private class CleartextChunkSaver implements RemovalListener<Long, ByteBuffer> {

		@Override
		public void onRemoval(RemovalNotification<Long, ByteBuffer> notification) {
			long chunkIndex = notification.getKey();
			if (openOptions.contains(StandardOpenOption.WRITE) && chunkIndex * cryptor.fileContentCryptor().cleartextChunkSize() < size()) {
				LOG.debug("save chunk" + chunkIndex);
				long ciphertextPos = chunkIndex * cryptor.fileContentCryptor().ciphertextChunkSize() + cryptor.fileHeaderCryptor().headerSize();
				ByteBuffer cleartextBuf = notification.getValue().asReadOnlyBuffer();
				cleartextBuf.flip();
				ByteBuffer ciphertextBuf = cryptor.fileContentCryptor().encryptChunk(cleartextBuf, chunkIndex, header);
				try {
					ch.write(ciphertextBuf, ciphertextPos);
				} catch (IOException e) {
					ioExceptionsDuringWrite.add(e);
				}
			}
		}

	}

}
