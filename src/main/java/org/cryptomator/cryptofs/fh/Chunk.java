/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.fh;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.String.format;

/**
 * A chunk of plaintext data. It has these rules:
 * <ol>
 *     <li>Capacity of {@code data} is always the cleartext chunk size</li>
 *     <li>During creation, {@code data}'s limit is the chunk's size (last chunk of a file may be smaller)</li>
 *     <li>Writes need to adjust the limit and mark this chunk dirty</li>
 *     <li>Reads need to respect the limit and must not change it</li>
 *     <li>When no longer used, the cleartext ByteBuffer may be recycled</li>
 * </ol>
 */
public record Chunk(ByteBuffer data, AtomicBoolean dirty) {

	public Chunk(ByteBuffer data, boolean dirty) {
		this(data, new AtomicBoolean(dirty));
	}

	public boolean isDirty() {
		return dirty.get();
	}

}
