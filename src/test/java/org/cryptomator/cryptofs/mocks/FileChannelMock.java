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

	private int failOnNextOperations = 0;
	private IOException error;

	private boolean closed = false;
	private SeekableByteChannelMock delegate;

	public FileChannelMock(int maxSize) {
		delegate = new SeekableByteChannelMock(maxSize);
	}

	public void setFailOnNextOperations(IOException error, int number) {
		this.failOnNextOperations = number;
		this.error = error;
	}

	public void setFailOnNextOperation(IOException error) {
		setFailOnNextOperations(error, 1);
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
		failIfRequired();
		return delegate.read(dst);
	}

	private void failIfRequired() throws IOException {
		if (failOnNextOperations-- > 0) {
			throw error;
		}
	}

	@Override
	public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
		assertNotClosed();
		failIfRequired();
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
		failIfRequired();
		return delegate.write(src);
	}

	@Override
	public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
		assertNotClosed();
		failIfRequired();
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
		failIfRequired();
		return delegate.position();
	}

	@Override
	public FileChannel position(long newPosition) throws IOException {
		assertNotClosed();
		failIfRequired();
		delegate.position(newPosition);
		return this;
	}

	@Override
	public long size() throws IOException {
		assertNotClosed();
		failIfRequired();
		return delegate.size();
	}

	@Override
	public FileChannel truncate(long size) throws IOException {
		assertNotClosed();
		failIfRequired();
		delegate.truncate(size);
		return this;
	}

	@Override
	public void force(boolean metaData) throws IOException {
		assertNotClosed();
		failIfRequired();
	}

	@Override
	public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
		assertNotClosed();
		failIfRequired();
		ByteBuffer buffer = ByteBuffer.allocate((int) count);
		int result = read(buffer, position);
		buffer.flip();
		target.write(buffer);
		return result;
	}

	@Override
	public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
		assertNotClosed();
		failIfRequired();
		ByteBuffer buffer = ByteBuffer.allocate((int) count);
		src.read(buffer);
		buffer.flip();
		return write(buffer, position);
	}

	@Override
	public int read(ByteBuffer dst, long position) throws IOException {
		assertNotClosed();
		failIfRequired();
		long previous = position();
		position(position);
		int result = delegate.read(dst);
		position(previous);
		return result;
	}

	@Override
	public int write(ByteBuffer src, long position) throws IOException {
		assertNotClosed();
		failIfRequired();
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
		failIfRequired();
		closed = true;
	}

	private void assertNotClosed() throws ClosedChannelException {
		if (closed) {
			throw new ClosedChannelException();
		}
	}

}
