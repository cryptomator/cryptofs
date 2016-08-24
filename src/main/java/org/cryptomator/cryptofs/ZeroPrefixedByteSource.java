package org.cryptomator.cryptofs;

import static java.lang.Math.min;

import java.nio.ByteBuffer;

class ZeroPrefixedByteSource implements ByteSource {

	private long amountOfZeroes;
	private final ByteBuffer source;

	public ZeroPrefixedByteSource(long amountOfZeroes, ByteBuffer source) {
		this.amountOfZeroes = amountOfZeroes;
		this.source = source;
	}
	
	@Override
	public boolean hasRemaining() {
		return amountOfZeroes > 0 || source.hasRemaining();
	}

	@Override
	public long remaining() {
		return amountOfZeroes + source.remaining();
	}

	@Override
	public void copyTo(ByteBuffer target) {
		if (amountOfZeroes > 0) {
			copyZeroesTo(target);
		}
		if (target.hasRemaining()) {
			copySourceTo(target);
		}
	}

	private void copyZeroesTo(ByteBuffer target) {
		int amountOfZeroesAsInt = (int)min(amountOfZeroes, Integer.MAX_VALUE);
		int amountOfZeroesToCopy = min(amountOfZeroesAsInt, target.remaining());
		ByteBuffer zeroes = ByteBuffer.allocate(amountOfZeroesToCopy);
		target.put(zeroes);
		amountOfZeroes -= amountOfZeroesToCopy;
	}

	private void copySourceTo(ByteBuffer target) {
		int originalLimit = source.limit();
		int limit = min(source.limit(), source.position() + target.remaining());
		source.limit(limit);
		target.put(source);
		source.limit(originalLimit);
	}

}
