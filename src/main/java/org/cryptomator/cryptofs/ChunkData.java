/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.lang.Math.max;
import static java.lang.Math.min;

import java.nio.ByteBuffer;

class ChunkData {
	
	private final ByteBuffer bytes;
	private boolean written;
	private int length;
	
	private ChunkData(ByteBuffer bytes, int length) {
		this.bytes = bytes;
		this.written = false;
		this.length = length;
	}
	
	public static ChunkData wrap(ByteBuffer bytes) {
		return new ChunkData(bytes, bytes.limit());
	}

	public static ChunkData emptyWithSize(int size) {
		return new ChunkData(ByteBuffer.allocate(size), 0);
	}
	
	public boolean wasWritten() {
		return written;
	}
	
	public CopyWithoutDirection copyData() {
		return copyDataStartingAt(0);
	}
	
	public CopyWithoutDirection copyDataStartingAt(int offset) {
		return new CopyWithoutDirection() {
			@Override
			public void to(ByteBuffer target) {
				bytes.limit(min(length, target.remaining() + offset));
				bytes.position(offset);
				target.put(bytes);
			}
			@Override
			public void from(ByteBuffer source) {
				from(ByteSource.from(source));
			}
			@Override
			public void from(ByteSource source) {
				written = true;
				bytes.limit(bytes.capacity());
				bytes.position(offset);
				source.copyTo(bytes);
				length = max(length, bytes.position());
			}
		};
	}

	public ByteBuffer asReadOnlyBuffer() {
		ByteBuffer readOnlyBuffer = bytes.asReadOnlyBuffer();
		readOnlyBuffer.position(0);
		readOnlyBuffer.limit(length);
		return readOnlyBuffer;
	}
	
	public interface CopyWithoutDirection {
		
		void to(ByteBuffer target);
		
		void from(ByteBuffer source);

		void from(ByteSource source);
		
	}
	
}
