package org.cryptomator.cryptofs.util;

import java.nio.ByteBuffer;

public class ByteBuffers {

	public static RepeatWithoutCount repeat(int value) {
		return count -> () -> {
			ByteBuffer buffer = ByteBuffer.allocate(count);
			while (buffer.hasRemaining()) {
				buffer.put((byte) value);
			}
			buffer.flip();
			return buffer;
		};
	}

	public interface RepeatWithoutCount {

		ByteBufferFactory times(int count);

	}

	public interface ByteBufferFactory {

		ByteBuffer asByteBuffer();

	}

}
