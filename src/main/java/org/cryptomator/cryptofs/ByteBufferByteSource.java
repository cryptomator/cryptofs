package org.cryptomator.cryptofs;

import static java.lang.Math.min;

import java.nio.ByteBuffer;

class ByteBufferByteSource implements ByteSource {

	private final ByteBuffer source;	
	
	public ByteBufferByteSource(ByteBuffer source) {
		this.source = source;
	}

	@Override
	public boolean hasRemaining() {
		return source.hasRemaining();
	}

	@Override
	public long remaining() {
		return source.remaining();
	}

	@Override
	public void copyTo(ByteBuffer target) {
		int originalLimit = source.limit();
		int limit = min(source.limit(), source.position() + target.remaining());
		source.limit(limit);
		target.put(source);
		source.limit(originalLimit);
	}
	
}
