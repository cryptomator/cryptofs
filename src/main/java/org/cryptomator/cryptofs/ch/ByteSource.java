/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.ch;

import static java.lang.Math.min;

import java.nio.ByteBuffer;

interface ByteSource {

	static ByteSource from(ByteBuffer buffer) {
		return new ByteBufferByteSource(buffer);
	}

	static ZeroPrefixedByteSourceWithoutBuffer repeatingZeroes(long amountOfZeroes) {
		return buffer -> new ZeroPrefixedByteSource(amountOfZeroes, buffer);
	}

	boolean hasRemaining();

	long remaining();

	/**
	 * <p>
	 * Copies as many bytes as possible from this {@code ByteSource} to the given {@link ByteBuffer}.
	 * <p>
	 * That means after this operation either {@link ByteBuffer#remaining()} or {@link ByteSource#remaining()} or both will return zero.
	 * 
	 * @param buffer the byte buffer to copy bytes to.
	 */
	void copyTo(ByteBuffer buffer);

	interface ZeroPrefixedByteSourceWithoutBuffer {

		ByteSource followedBy(ByteBuffer delegate);

	}

	class ByteBufferByteSource implements ByteSource {

		private final ByteBuffer source;

		private ByteBufferByteSource(ByteBuffer source) {
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

	class ZeroPrefixedByteSource implements ByteSource {

		private long amountOfZeroes;
		private final ByteBuffer source;

		private ZeroPrefixedByteSource(long amountOfZeroes, ByteBuffer source) {
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
			int amountOfZeroesAsInt = (int) min(amountOfZeroes, Integer.MAX_VALUE);
			int amountOfZeroesToCopy = min(amountOfZeroesAsInt, target.remaining());
			ByteBuffer zeroes = ByteBuffer.allocate(amountOfZeroesToCopy); // TODO: do we really need ZEROs? Or is it sufficient to simply SKIP to the target pos?
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

}
