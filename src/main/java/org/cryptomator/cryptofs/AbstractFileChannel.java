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
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

/**
 * TODO Not thread-safe.
 */
abstract class AbstractFileChannel extends FileChannel {

	private static final int BUFFER_SIZE = 4096;
	private long position;

	@Override
	public long position() throws IOException {
		return position;
	}

	@Override
	public FileChannel position(long newPosition) throws IOException {
		position = newPosition;
		return this;
	}

	@Override
	public int read(ByteBuffer dst) throws IOException {
		int read = read(dst, position);
		position += read;
		return read;
	}

	@Override
	public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
		boolean completed = false;
		try {
			begin();
			long totalRead = 0;
			for (int i = offset; i < length; i++) {
				int read = read(dsts[i]);
				if (read == -1 && totalRead == 0) {
					return -1;
				} else if (read == -1) {
					completed = true;
					return totalRead;
				} else {
					totalRead += read;
				}
			}
			completed = true;
			return totalRead;
		} finally {
			end(completed);
		}
	}

	@Override
	public int write(ByteBuffer src) throws IOException {
		int written = write(src, position);
		position += written;
		return written;
	}

	@Override
	public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
		boolean completed = false;
		try {
			begin();
			long totalWritten = 0;
			for (int i = offset; i < length; i++) {
				totalWritten += write(srcs[i]);
			}
			completed = true;
			return totalWritten;
		} finally {
			end(completed);
		}
	}

	@Override
	public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
		ByteBuffer buf = ByteBuffer.allocate((int) Math.min(count, BUFFER_SIZE));
		long transferred = 0;
		while (transferred < count) {
			buf.clear();
			int read = this.read(buf, position + transferred);
			if (read == -1) {
				break;
			} else {
				buf.flip();
				buf.limit((int) Math.min(buf.limit(), count - transferred));
				transferred += target.write(buf);
			}
		}
		return transferred;
	}

	@Override
	public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
		if (position > size()) {
			return 0;
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
	}

}
