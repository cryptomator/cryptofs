package org.cryptomator.cryptofs.ch;

import java.io.IOException;
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

import static java.lang.Math.min;

public abstract class AbstractFileChannel extends FileChannel {

	private static final int BUFFER_SIZE = 4096;

	/*
	 * Copied from Jimfs (Apache License 2.0) Copyright 2013 Google Inc.
	 * --- BEGIN ---
	 */
	private final Set<Thread> blockingThreads = new HashSet<>();

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
	public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
		assertOpen();
		assertReadable();
		try {
			beginBlocking();
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
		} finally {
			endBlocking(true);
		}
	}

	@Override
	public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
		assertOpen();
		assertWritable();
		try {
			beginBlocking();
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
		} finally {
			endBlocking(true);
		}
	}

}
