/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.ch;

import org.cryptomator.cryptolib.common.ByteBuffers;

import java.nio.ByteBuffer;

import static java.lang.Math.min;

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
				ByteBuffers.copy(source, target);
			} else {
				target.put(source);
			}
		}

	}

	class ZeroPrefixedByteSource implements ByteSource {

		private static final ByteBuffer ZEROES = ByteBuffer.allocate(4069);

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
			while (amountOfZeroes > 0) {
				copyZeroesTo(target);
			}
			if (target.hasRemaining()) {
				copySourceTo(target);
			}
		}

		private void copyZeroesTo(ByteBuffer target) {
			var zeroes = ZEROES.asReadOnlyBuffer(); // use a view to protect original pos/limit
			int amountOfZeroesToCopy = (int) min(amountOfZeroes, zeroes.remaining());
			zeroes.limit(amountOfZeroesToCopy);
			amountOfZeroes -= ByteBuffers.copy(zeroes, target);
		}

		private void copySourceTo(ByteBuffer target) {
			if (source.remaining() > target.remaining()) {
				ByteBuffers.copy(source, target);
			} else {
				target.put(source);
			}
		}

	}

}
