package org.cryptomator.cryptofs.mocks;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

public class FileChannelMock extends FileChannel {

	private boolean closed = false;
	private SeekableByteChannelMock delegate;

	public FileChannelMock(int maxSize) {
		delegate = new SeekableByteChannelMock(maxSize);
	}

	public FileChannelMock(ByteBuffer data) {
		delegate = new SeekableByteChannelMock(data);
	}

	public ByteBuffer data() {
		return delegate.data();
	}

	@Override
	public int read(ByteBuffer dst) throws IOException {
		assertNotClosed();
		return delegate.read(dst);
	}

	@Override
	public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
		assertNotClosed();
		long result = 0;
		for (int i = offset; i < offset + length; i++) {
			int expected = dsts[i].remaining();
			int read = read(dsts[i]);
			if (read == -1) {
				break;
			}
			result += read;
			if (read != expected) {
				break;
			}
		}
		return result;
	}

	@Override
	public int write(ByteBuffer src) throws IOException {
		assertNotClosed();
		return delegate.write(src);
	}

	@Override
	public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
		assertNotClosed();
		long result = 0;
		for (int i = offset; i < offset + length; i++) {
			int written = write(srcs[i]);
			result += written;
		}
		return result;
	}

	@Override
	public long position() throws IOException {
		assertNotClosed();
		return delegate.position();
	}

	@Override
	public FileChannel position(long newPosition) throws IOException {
		assertNotClosed();
		delegate.position(newPosition);
		return this;
	}

	@Override
	public long size() throws IOException {
		assertNotClosed();
		return delegate.size();
	}

	@Override
	public FileChannel truncate(long size) throws IOException {
		delegate.truncate(size);
		return this;
	}

	@Override
	public void force(boolean metaData) throws IOException {
		assertNotClosed();
	}

	@Override
	public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
		assertNotClosed();
		ByteBuffer buffer = ByteBuffer.allocate((int) count);
		int result = read(buffer, position);
		buffer.flip();
		target.write(buffer);
		return result;
	}

	@Override
	public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
		assertNotClosed();
		ByteBuffer buffer = ByteBuffer.allocate((int) count);
		src.read(buffer);
		buffer.flip();
		return write(buffer, position);
	}

	@Override
	public int read(ByteBuffer dst, long position) throws IOException {
		assertNotClosed();
		long previous = position();
		position(position);
		int result = delegate.read(dst);
		position(previous);
		return result;
	}

	@Override
	public int write(ByteBuffer src, long position) throws IOException {
		assertNotClosed();
		long previous = position();
		position(position);
		int result = delegate.write(src);
		position(previous);
		return result;
	}

	@Override
	public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
		throw new UnsupportedOperationException("only a partial mock");
	}

	@Override
	public FileLock lock(long position, long size, boolean shared) throws IOException {
		throw new UnsupportedOperationException("only a partial mock");
	}

	@Override
	public FileLock tryLock(long position, long size, boolean shared) throws IOException {
		throw new UnsupportedOperationException("only a partial mock");
	}

	@Override
	protected void implCloseChannel() throws IOException {
		closed = true;
	}

	private void assertNotClosed() throws ClosedChannelException {
		if (closed) {
			throw new ClosedChannelException();
		}
	}

}
