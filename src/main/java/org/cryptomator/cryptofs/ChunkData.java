package org.cryptomator.cryptofs;

import java.nio.ByteBuffer;

class ChunkData {
	
	private final ByteBuffer bytes;
	private final boolean written;
	
	private ChunkData(ByteBuffer bytes, boolean written) {
		this.bytes = bytes;
		this.written = written;
	}

	public static ChunkData writtenChunkData(ByteBuffer bytes) {
		return new ChunkData(bytes, true);
	}

	public static ChunkData readChunkData(ByteBuffer bytes) {
		return new ChunkData(bytes, false);
	}
	
	public ByteBuffer bytes() {
		return bytes;
	}
	
	public boolean wasWritten() {
		return written;
	}
	
}
