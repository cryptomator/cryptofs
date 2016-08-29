/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.lang.Math.min;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Objects;

class CryptoFileChannel extends FileChannel {

	private static final int BUFFER_SIZE = 4096;

	private final OpenCryptoFile openCryptoFile;
	private final EffectiveOpenOptions options;
	private long position = 0;

	/**
	 * @throws IOException
	 * @throws ClosedChannelException if the openCryptoFile has already been closed
	 */
	public CryptoFileChannel(OpenCryptoFile openCryptoFile, EffectiveOpenOptions options) throws IOException {
		this.openCryptoFile = Objects.requireNonNull(openCryptoFile);
		this.options = Objects.requireNonNull(options);
		this.openCryptoFile.open(options);
	}

	@Override
	public synchronized long position() throws IOException {
		assertOpen();
		return position;
	}

	@Override
	public synchronized FileChannel position(long newPosition) throws IOException {
		assertOpen();
		if (newPosition < 0) {
			throw new IllegalArgumentException();
		}
		position = newPosition;
		return this;
	}

	@Override
	public synchronized int read(ByteBuffer dst) throws IOException {
		assertOpen();
		assertReadable();
		return blockingIo(() -> internalRead(dst));
	}

	@Override
	public synchronized int write(ByteBuffer src) throws IOException {
		assertOpen();
		assertWritable();
		return blockingIo(() -> internalWrite(src)).intValue();
	}

	@Override
	public synchronized int read(ByteBuffer target, long position) throws IOException {
		assertOpen();
		assertReadable();
		return blockingIo(() -> internalRead(target, position));
	}

	@Override
	public synchronized int write(ByteBuffer source, long offset) throws IOException {
		assertOpen();
		assertWritable();
		return blockingIo(() -> internalWrite(source, offset));
	}

	@Override
	public synchronized long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
		assertOpen();
		assertReadable();
		return blockingIo(() -> {
			long totalRead = 0;
			for (int i = 0; i < length; i++) {
				int read = internalRead(dsts[i + offset]);
				if (read == -1 && totalRead == 0) {
					return -1L;
				} else if (read == -1) {
					return totalRead;
				} else {
					totalRead += read;
				}
			}
			return totalRead;
		});
	}

	@Override
	public synchronized long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
		assertOpen();
		assertWritable();
		return blockingIo(() -> {
			long totalWritten = 0;
			for (int i = 0; i < length; i++) {
				totalWritten += internalWrite(srcs[offset + i]);
			}
			return totalWritten;
		});
	}

	@Override
	public synchronized long transferTo(long position, long count, WritableByteChannel target) throws IOException {
		assertOpen();
		assertReadable();
		return blockingIo(() -> {
			ByteBuffer buf = ByteBuffer.allocate((int) min(count, BUFFER_SIZE));
			long transferred = 0;
			while (transferred < count) {
				buf.clear();
				int read = internalRead(buf, position + transferred);
				if (read == -1) {
					break;
				} else {
					buf.flip();
					buf.limit((int) min(buf.limit(), count - transferred));
					transferred += target.write(buf);
				}
			}
			return transferred;
		});
	}

	@Override
	public synchronized long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
		assertOpen();
		assertWritable();
		return blockingIo(() -> {
			if (position > size()) {
				return 0L;
			}
			ByteBuffer buf = ByteBuffer.allocate((int) min(count, BUFFER_SIZE));
			long transferred = 0;
			while (transferred < count) {
				buf.clear();
				int read = src.read(buf);
				if (read == -1) {
					break;
				} else {
					buf.flip();
					buf.limit((int) min(buf.limit(), count - transferred));
					transferred += this.write(buf, position + transferred);
				}
			}
			return transferred;
		});
	}

	private long internalWrite(ByteBuffer src) throws IOException {
		if (options.append()) {
			return openCryptoFile.append(options, src);
		} else {
			long positionBeforeWrite = position();
			int written = openCryptoFile.write(options, src, positionBeforeWrite);
			position(positionBeforeWrite + written);
			return written;
		}
	}

	private int internalRead(ByteBuffer dst) throws IOException {
		long positionBeforeRead = position();
		int read = openCryptoFile.read(dst, positionBeforeRead);
		if (read >= 0) {
			position(positionBeforeRead + read);
		}
		return read;
	}

	private int internalWrite(ByteBuffer source, long position) throws IOException {
		return openCryptoFile.write(options, source, position);
	}

	private int internalRead(ByteBuffer target, long position) throws IOException {
		return openCryptoFile.read(target, position);
	}

	@Override
	public long size() throws ClosedChannelException {
		assertOpen();
		return openCryptoFile.size();
	}

	@Override
	public synchronized FileChannel truncate(long size) throws IOException {
		assertOpen();
		assertWritable();
		openCryptoFile.truncate(size);
		position = min(size, position);
		return this;
	}

	@Override
	public void force(boolean metaData) throws IOException {
		assertOpen();
		openCryptoFile.force(metaData, options);
	}

	@Override
	public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public FileLock lock(long position, long size, boolean shared) throws IOException {
		assertOpen();
		return blockingIo(() -> {
			FileLock delegate = openCryptoFile.lock(position, size, shared);
			CryptoFileLock result = CryptoFileLock.builder() //
					.withDelegate(delegate) //
					.withChannel(this) //
					.withPosition(position) //
					.withSize(size) //
					.thatIsShared(shared).build();
			return result;
		});
	}

	@Override
	public FileLock tryLock(long position, long size, boolean shared) throws IOException {
		assertOpen();
		FileLock delegate = openCryptoFile.tryLock(position, size, shared);
		if (delegate == null) {
			return null;
		}
		CryptoFileLock result = CryptoFileLock.builder() //
				.withDelegate(delegate) //
				.withChannel(this) //
				.withPosition(position) //
				.withSize(size) //
				.thatIsShared(shared).build();
		return result;

	}

	@Override
	protected void implCloseChannel() throws IOException {
		openCryptoFile.close(options);
	}

	private void assertWritable() throws IOException {
		if (!options.writable()) {
			throw new IOException("Channel not writable");
		}
	}

	private void assertReadable() throws IOException {
		if (!options.readable()) {
			throw new IOException("Channel not readable");
		}
	}

	private <T> T blockingIo(SupplierThrowingException<T, IOException> supplier) throws IOException {
		boolean completed = false;
		try {
			begin();
			T result = supplier.get();
			completed = true;
			return result;
		} finally {
			end(completed);
		}
	}

	private void assertOpen() throws ClosedChannelException {
		if (!isOpen()) {
			throw new ClosedChannelException();
		}
	}

}
