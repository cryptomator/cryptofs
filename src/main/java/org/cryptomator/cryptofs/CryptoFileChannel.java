/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.cryptomator.cryptolib.Constants.CHUNK_SIZE;
import static org.cryptomator.cryptolib.Constants.PAYLOAD_SIZE;

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

import org.cryptomator.cryptolib.AuthenticationFailedException;
import org.cryptomator.cryptolib.Cryptor;
import org.cryptomator.cryptolib.FileHeader;
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

	public CryptoFileChannel(Cryptor cryptor, Path ciphertextPath, Set<OpenOption> options) throws IOException {
		this.cryptor = cryptor;
		Set<OpenOption> adjustedOptions = new HashSet<>(options);
		adjustedOptions.remove(StandardOpenOption.APPEND);
		adjustedOptions.add(StandardOpenOption.READ);
		openOptions = Collections.unmodifiableSet(adjustedOptions);
		ch = FileChannel.open(ciphertextPath, adjustedOptions);
		if (adjustedOptions.contains(StandardOpenOption.CREATE_NEW) || adjustedOptions.contains(StandardOpenOption.CREATE) && ch.size() == 0) {
			header = cryptor.fileHeaderCryptor().create();
		} else {
			ByteBuffer existingHeaderBuf = ByteBuffer.allocate(FileHeader.SIZE);
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
		while (dst.hasRemaining()) {
			long pos = position + read;
			long chunkIndex = pos / PAYLOAD_SIZE;
			int offset = (int) pos % PAYLOAD_SIZE;
			int len = Math.min(dst.remaining(), PAYLOAD_SIZE - offset);
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
		while (src.hasRemaining()) {
			long pos = position + written;
			long chunkIndex = pos / PAYLOAD_SIZE;
			int offset = (int) pos % PAYLOAD_SIZE;
			int len = Math.min(src.remaining(), PAYLOAD_SIZE - offset);
			if (pos + len > size()) {
				// append
				header.getPayload().setFilesize(pos + len);
			}
			if (len == PAYLOAD_SIZE) {
				// complete chunk, no need to load and decrypt from file:
				cleartextChunks.put(chunkIndex, ByteBuffer.allocate(PAYLOAD_SIZE));
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
		return header.getPayload().getFilesize();
	}

	@Override
	public FileChannel truncate(long size) throws IOException {
		ch.truncate(FileHeader.SIZE);
		header.getPayload().setFilesize(Math.min(size, size()));
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
			force(true);
			// TODO append size obfuscation padding?
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
			long ciphertextPos = chunkIndex * CHUNK_SIZE + FileHeader.SIZE;
			ByteBuffer ciphertextBuf = ByteBuffer.allocate(CHUNK_SIZE);
			int read = ch.read(ciphertextBuf, ciphertextPos);
			if (read == -1) {
				// append
				return ByteBuffer.allocate(PAYLOAD_SIZE);
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
			if (openOptions.contains(StandardOpenOption.WRITE) && chunkIndex * PAYLOAD_SIZE < size()) {
				LOG.debug("save chunk" + chunkIndex);
				long ciphertextPos = chunkIndex * CHUNK_SIZE + FileHeader.SIZE;
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
