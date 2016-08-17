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
import static java.nio.file.StandardOpenOption.WRITE;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.OpenOption;
import java.util.Set;

import org.cryptomator.cryptofs.OpenCryptoFile.AlreadyClosedException;

class CryptoFileChannel extends FileChannel {

	private static final int BUFFER_SIZE = 4096;

	private final OpenCryptoFile openCryptoFile;
	private final boolean writable;
	private long position = 0;

	/**
	 * @throws AlreadyClosedException if the openCryptoFile has already been closed
	 */
	public CryptoFileChannel(OpenCryptoFile openCryptoFile, Set<? extends OpenOption> options) throws IOException {
		this.openCryptoFile = openCryptoFile;
		this.writable = options.contains(WRITE);
	}

	@Override
	public synchronized long position() throws IOException {
		return position;
	}

	@Override
	public synchronized FileChannel position(long newPosition) throws IOException {
		position = newPosition;
		return this;
	}

	@Override
	public synchronized int read(ByteBuffer dst) throws IOException {
		return blockingIo(() -> internalRead(dst));
	}

	@Override
	public synchronized int write(ByteBuffer src) throws IOException {
		assertWritable();
		return blockingIo(() -> internalWrite(src)).intValue();
	}

	@Override
	public synchronized int read(ByteBuffer target, long position) throws IOException {
		return blockingIo(() -> internalRead(target, position));
	}

	@Override
	public synchronized int write(ByteBuffer source, long offset) throws IOException {
		assertWritable();
		return blockingIo(() -> internalWrite(source, offset));
	}

	@Override
	public synchronized long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
		return blockingIo(() -> {
			long totalRead = 0;
			for (int i = offset; i < length; i++) {
				int read = internalRead(dsts[i]);
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
		assertWritable();
		return blockingIo(() -> {
			long totalWritten = 0;
			for (int i = offset; i < length; i++) {
				totalWritten += internalWrite(srcs[i]);
			}
			return totalWritten;
		});
	}

	@Override
	public synchronized long transferTo(long position, long count, WritableByteChannel target) throws IOException {
		return blockingIo(() -> {
			ByteBuffer buf = ByteBuffer.allocate((int) Math.min(count, BUFFER_SIZE));
			long transferred = 0;
			while (transferred < count) {
				buf.clear();
				int read = internalRead(buf, position + transferred);
				if (read == -1) {
					break;
				} else {
					buf.flip();
					buf.limit((int) Math.min(buf.limit(), count - transferred));
					transferred += target.write(buf);
				}
			}
			return transferred;
		});
	}

	@Override
	public synchronized long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
		assertWritable();
		return blockingIo(() -> {
			if (position > size()) {
				return 0L;
			}
			ByteBuffer buf = ByteBuffer.allocate((int) Math.min(count, BUFFER_SIZE));
			long transferred = 0;
			while (transferred < count) {
				buf.clear();
				int read = src.read(buf);
				if (read == -1) {
					break;
				} else {
					buf.flip();
					buf.limit((int) Math.min(buf.limit(), count - transferred));
					transferred += this.write(buf, position + transferred);
				}
			}
			return transferred;
		});
	}

	private long internalWrite(ByteBuffer src) throws IOException {
		long positionBeforeWrite = position();
		int written = openCryptoFile.write(src, positionBeforeWrite);
		position(positionBeforeWrite + written);
		return written;
	}

	private int internalRead(ByteBuffer dst) throws IOException {
		long positionBeforeRead = position();
		int read = openCryptoFile.read(dst, positionBeforeRead);
		position(positionBeforeRead + read);
		return read;
	}

	private int internalWrite(ByteBuffer source, long position) throws IOException {
		return openCryptoFile.write(source, position);
	}

	private int internalRead(ByteBuffer target, long position) throws IOException {
		return openCryptoFile.read(target, position);
	}

	@Override
	public long size() {
		return openCryptoFile.size();
	}

	@Override
	public synchronized FileChannel truncate(long size) throws IOException {
		assertWritable();
		openCryptoFile.truncate(size);
		position = min(size, position);
		return this;
	}

	@Override
	public void force(boolean metaData) throws IOException {
		openCryptoFile.force(metaData, writable);
	}

	@Override
	public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public FileLock lock(long position, long size, boolean shared) throws IOException {
		return blockingIo(() -> {
			FileLock delegate = openCryptoFile.lock(position, size, shared);
			CryptoFileLock result = CryptoFileLock.builder() //
					.withDelegate(delegate)
					.withChannel(this)
					.withPosition(position)
					.withSize(size)
					.thatIsShared(shared)
					.build();
			return result;
		});
	}

	@Override
	public FileLock tryLock(long position, long size, boolean shared) throws IOException {
		return blockingIo(() -> {
			FileLock delegate = openCryptoFile.lock(position, size, shared);
			if (delegate == null) {
				return null;
			}
			CryptoFileLock result = CryptoFileLock.builder() //
					.withDelegate(delegate)
					.withChannel(this)
					.withPosition(position)
					.withSize(size)
					.thatIsShared(shared)
					.build();
			return result;
		});
		
	}

	@Override
	protected void implCloseChannel() throws IOException {
		openCryptoFile.close(writable);
	}

	private void assertWritable() throws IOException {
		if (!writable) {
			throw new IOException("Channel not writable");
		}
	}

	private <T> T blockingIo(SupplierThrowingException<T,IOException> supplier) throws IOException {
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

}
