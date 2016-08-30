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
	 * <p>Copies as many bytes as possible from this {@code ByteSource} to the given {@link ByteBuffer}.
	 * <p>That means after this operation either {@link ByteBuffer#remaining()} or {@link ByteSource#remaining()} or both will return zero.
	 * 
	 * @param buffer the byte buffer to copy bytes to.
	 */
	void copyTo(ByteBuffer buffer);

	interface ZeroPrefixedByteSourceWithoutBuffer {
		
		ByteSource followedBy(ByteBuffer delegate);
		
	}

}
