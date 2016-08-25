package org.cryptomator.cryptofs;

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
		if (source.remaining() > target.remaining()) {
			int originalLimit = source.limit();
			source.limit(source.position() + target.remaining());
			target.put(source);
			source.limit(originalLimit);
		} else {
			target.put(source);
		}
	}
	
}