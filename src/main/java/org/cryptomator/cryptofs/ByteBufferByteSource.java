/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.nio.ByteBuffer;

class ByteBufferByteSource implements ByteSource {

	private final ByteBuffer source;	
	
	public ByteBufferByteSource(ByteBuffer source) {
		this.source = source;
	}
	
	ByteBuffer getBuffer() {
		return source;
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