/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

class CryptoFileLock extends FileLock {

	private final FileLock delegate;
	
	private CryptoFileLock(Builder builder) {
		super(builder.channel, builder.position, builder.size, builder.shared);
		this.delegate = builder.delegate;
	}
	
	FileLock delegate() {
		return delegate;
	}

	@Override
	public boolean isValid() {
		return delegate.isValid() && channel().isOpen();
	}

	@Override
	public void release() throws IOException {
		delegate.release();
	}
	
	public static Builder builder() {
		return new Builder();
	}
	
	public static class Builder {
		
		private FileLock delegate;
		private FileChannel channel;
		private Long position;
		private Long size;
		private Boolean shared;
		
		private Builder() {}
		
		public Builder withDelegate(FileLock delegate) {
			this.delegate = delegate;
			return this;
		}
		
		public Builder withChannel(FileChannel channel) {
			this.channel = channel;
			return this;	
		}
		
		public Builder withPosition(long position) {
			this.position = position;
			return this;
		}
		
		public Builder withSize(long size) {
			this.size = size;
			return this;
		}
		
		public Builder thatIsShared(boolean shared) {
			this.shared = shared;
			return this;
		}
		
		public CryptoFileLock build() {
			validate();
			return new CryptoFileLock(this);
		}

		private void validate() {
			assertNonNull(delegate, "delegate");
			assertNonNull(channel, "channel");
			assertNonNull(position, "position");
			assertNonNull(size, "size");
			assertNonNull(shared, "shared");
		}

		private void assertNonNull(Object value, String name) {
			if (value == null) {
				throw new IllegalStateException(name + " must be set");
			}
		}
		
	}

}
