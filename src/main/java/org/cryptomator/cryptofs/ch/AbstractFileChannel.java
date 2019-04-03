package org.cryptomator.cryptofs.ch;

import com.google.common.base.Preconditions;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;

import static java.lang.Math.min;

public abstract class AbstractFileChannel extends FileChannel {

	private static final int BUFFER_SIZE = 4096;

	private final Set<Thread> blockingThreads = new HashSet<>();
	private final ReadWriteLock readWriteLock;
	protected long position;

	public AbstractFileChannel(ReadWriteLock readWriteLock) {
		this.readWriteLock = readWriteLock;
	}

	/*
	 * Copied from Jimfs (Apache License 2.0) Copyright 2013 Google Inc.
	 * --- BEGIN ---
	 */

	/**
	 * Begins a blocking operation, making the operation interruptible. Returns {@code true} if the
	 * channel was open and the thread was added as a blocking thread; returns {@code false} if the
	 * channel was closed.
	 */
	protected boolean beginBlocking() {
		begin();
		synchronized (blockingThreads) {
			if (isOpen()) {
				blockingThreads.add(Thread.currentThread());
				return true;
			}
			return false;
		}
	}

	/**
	 * Ends a blocking operation, throwing an exception if the thread was interrupted while blocking
	 * or if the channel was closed from another thread.
	 */
	protected void endBlocking(boolean completed) throws AsynchronousCloseException {
		synchronized (blockingThreads) {
			blockingThreads.remove(Thread.currentThread());
		}
		end(completed);
	}

	@Override
	protected void implCloseChannel() throws IOException {
		synchronized (blockingThreads) {
			for (Thread thread : blockingThreads) {
				thread.interrupt();
			}
		}
	}

	/*
	 * --- END ---
	 */

	@Override
	public long position() throws IOException {
		assertOpen();
		return position;
	}

	@Override
	public FileChannel position(long newPosition) throws IOException {
		Preconditions.checkArgument(newPosition >= 0);
		assertOpen();
		position = newPosition;
		return this;
	}

	protected void assertWritable() throws IOException {
		if (!isWritable()) {
			throw new NonWritableChannelException();
		}
	}

	protected abstract boolean isWritable();

	protected void assertReadable() throws IOException {
		if (!isReadable()) {
			throw new NonReadableChannelException();
		}
	}

	protected abstract boolean isReadable();

	protected void assertOpen() throws ClosedChannelException {
		if (!isOpen()) {
			throw new ClosedChannelException();
		}
	}

	@Override
	public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
		assertOpen();
		assertReadable();
		try {
			beginBlocking();
			long totalRead = 0;
			for (int i = offset; i < offset+length; i++) {
				int read = read(dsts[i]);
				if (read == -1 && totalRead == 0) {
					return -1L;
				} else if (read == -1) {
					return totalRead;
				} else {
					totalRead += read;
				}
			}
			return totalRead;
		} finally {
			endBlocking(true);
		}
	}

	@Override
	public int read(ByteBuffer dst) throws IOException {
		int read = read(dst, position);
		if (read != -1) {
			position += read;
		}
		return read;
	}

	@Override
	public int read(ByteBuffer dst, long position) throws IOException {
		assertOpen();
		assertReadable();
		boolean completed = false;
		try {
			beginBlocking();
			readWriteLock.readLock().lockInterruptibly();
			try {
				int read = readLocked(dst, position);
				completed = true;
				return read;
			} finally {
				readWriteLock.readLock().unlock();
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new InterruptedIOException();
		} finally {
			endBlocking(completed);
		}
	}

	/**
	 * @see #read(ByteBuffer, long)
	 */
	protected abstract int readLocked(ByteBuffer dst, long position) throws IOException;

	@Override
	public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
		assertOpen();
		assertWritable();
		try {
			beginBlocking();
			long totalWritten = 0;
			for (int i = offset; i < offset+length; i++) {
				totalWritten += write(srcs[i]);
			}
			return totalWritten;
		} finally {
			endBlocking(true);
		}
	}

	@Override
	public int write(ByteBuffer src) throws IOException {
		int written = write(src, position);
		position += written;
		return written;
	}

	@Override
	public int write(ByteBuffer src, long position) throws IOException {
		assertOpen();
		assertWritable();
		boolean completed = false;
		try {
			beginBlocking();
			readWriteLock.writeLock().lockInterruptibly();
			try {
				int written = writeLocked(src, position);
				completed = true;
				return written;
			} finally {
				readWriteLock.writeLock().unlock();
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new InterruptedIOException();
		} finally {
			endBlocking(completed);
		}
	}

	/**
	 * @see #write(ByteBuffer, long)
	 */
	protected abstract int writeLocked(ByteBuffer src, long position) throws IOException;

	@Override
	public FileChannel truncate(long size) throws IOException {
		assertOpen();
		assertWritable();
		boolean completed = false;
		try {
			beginBlocking();
			readWriteLock.writeLock().lockInterruptibly();
			try {
				truncateLocked(size);
				completed = true;
				return this;
			} finally {
				readWriteLock.writeLock().unlock();
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new InterruptedIOException();
		} finally {
			endBlocking(completed);
		}
	}

	/**
	 * @see #truncate(long)
	 */
	protected abstract void truncateLocked(long size) throws IOException;

	@Override
	public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
		assertOpen();
		assertReadable();
		boolean completed = false;
		try {
			beginBlocking();
			readWriteLock.readLock().lockInterruptibly();
			try {
				long transferred = transferToLocked(position, count, target);
				completed = true;
				return transferred;
			} finally {
				readWriteLock.readLock().unlock();
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new InterruptedIOException();
		} finally {
			endBlocking(completed);
		}
	}

	protected long transferToLocked(long position, long count, WritableByteChannel target) throws IOException {
		ByteBuffer buf = ByteBuffer.allocate((int) min(count, BUFFER_SIZE));
		long transferred = 0;
		while (transferred < count) {
			buf.clear();
			int read = read(buf, position + transferred);
			if (read == -1) {
				break;
			} else {
				buf.flip();
				buf.limit((int) min(buf.limit(), count - transferred));
				transferred += target.write(buf);
			}
		}
		return transferred;
	}

	@Override
	public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
		assertOpen();
		assertWritable();
		boolean completed = false;
		try {
			beginBlocking();
			readWriteLock.writeLock().lockInterruptibly();
			try {
				long transferred = transferFromLocked(src, position, count);
				completed = true;
				return transferred;
			} finally {
				readWriteLock.writeLock().unlock();
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new InterruptedIOException();
		} finally {
			endBlocking(completed);
		}
	}

	protected long transferFromLocked(ReadableByteChannel src, long position, long count) throws IOException {
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
	}

}
