/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.fh;

import static java.lang.Math.min;

import java.nio.ByteBuffer;

public interface ByteSource {

	static ByteSource from(ByteBuffer buffer) {
		return new ByteBufferByteSource(buffer);
	}

	static UndefinedNoisePrefixedByteSourceWithoutBuffer undefinedNoise(long numBytes) {
		return buffer -> new UndefinedNoisePrefixedByteSource(numBytes, buffer);
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

	interface UndefinedNoisePrefixedByteSourceWithoutBuffer {

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

	class UndefinedNoisePrefixedByteSource implements ByteSource {

		private long prefixLen;
		private final ByteBuffer source;

		private UndefinedNoisePrefixedByteSource(long prefixLen, ByteBuffer source) {
			this.prefixLen = prefixLen;
			this.source = source;
		}

		@Override
		public boolean hasRemaining() {
			return prefixLen > 0 || source.hasRemaining();
		}

		@Override
		public long remaining() {
			return prefixLen + source.remaining();
		}

		@Override
		public void copyTo(ByteBuffer target) {
			if (prefixLen > 0) {
				skip(target);
			}
			if (target.hasRemaining()) {
				copySourceTo(target);
			}
		}

		private void skip(ByteBuffer target) {
			int n = (int) min(prefixLen, target.remaining()); // known to fit into int due to 2nd param
			target.position(target.position() + n);
			prefixLen -= n;
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
