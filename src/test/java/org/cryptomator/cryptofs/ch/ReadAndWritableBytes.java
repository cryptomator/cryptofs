package org.cryptomator.cryptofs.ch;

import static java.lang.Math.max;
import static java.lang.Math.min;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Random;
import java.util.function.Function;

class ReadAndWritableBytes implements WritableByteChannel,ReadableByteChannel { 
	
	private final int INITIAL_CAPACITY = 1024;
	private final Function<Integer,Integer> MIN_GROWTH_FUNCTION = current -> current >> 1;
	
	private ByteBuffer data = ByteBuffer.allocate(INITIAL_CAPACITY);
	
	private boolean open = true;
	private int position = 0;
	private int size;
	
	private ReadAndWritableBytes() {}
	
	public static ReadAndWritableBytes random(int length) {
		ReadAndWritableBytes result = ReadAndWritableBytes.empty();
		Random random = new Random();
		byte[] buffer = new byte[length];
		random.nextBytes(buffer);
		result.write(ByteBuffer.wrap(buffer));
		result.position = 0;
		return result;
	}
	
	public static ReadAndWritableBytes empty() {
		return new ReadAndWritableBytes();
	}
	
	@Override
	public boolean isOpen() {
		return open;
	}

	@Override
	public void close() {
		open = false;
	}
	
	public byte[] toArray() {
		return toArray(0, size);
	}
	
	public byte[] toArray(int position, int length) {
		byte[] result = new byte[length];
		if (read(ByteBuffer.wrap(result), position) != length) {
			throw new IllegalArgumentException();
		}
		return result;
	}

	@Override
	public int read(ByteBuffer dst) throws IOException {
		int result = read(dst, position);
		if (result > 0) {
			position += result;
		}
		return result;
	}

	public int read(ByteBuffer dst, long position) {
		if (position >= size) {
			return -1;
		}
		data.limit(capacity());
		data.position((int)position);
		int amount = min(data.remaining(), dst.remaining());
		data.limit((int)position + amount);
		dst.put(data);
		return amount;
	}

	@Override
	public int write(ByteBuffer src) {
		int result = write(src, position);
		position += result;
		size = max(size, position);
		return result;
	}

	public int write(ByteBuffer source, int position) {
		int amount = source.remaining();
		int endOfWrite = position + amount;
		ensureCapacity(endOfWrite);
		data.limit(capacity());
		data.position(position);
		data.put(source);
		size = max(size, endOfWrite);
		return amount;
	}
	
	private int capacity() {
		return data.capacity();
	}
	
	private void ensureCapacity(int requiredCapacity) {
		if (capacity() >= requiredCapacity) {
			return;
		}
		int newCapacity = capacity() + MIN_GROWTH_FUNCTION.apply(capacity());
		if (newCapacity < requiredCapacity) {
			newCapacity = requiredCapacity;
		}
		ByteBuffer newBuffer = ByteBuffer.allocate(newCapacity);
		data.flip();
		newBuffer.put(data);
		data = newBuffer;
	}

}
