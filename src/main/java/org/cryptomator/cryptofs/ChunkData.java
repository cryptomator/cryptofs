package org.cryptomator.cryptofs;

import java.nio.ByteBuffer;

class ChunkData {

	public static ChunkData writtenChunkData(ByteBuffer bytes) {
		return new ChunkData(bytes, true);
	}

	public static ChunkData readChunkData(ByteBuffer bytes) {
		return new ChunkData(bytes, false);
	}
	
	private final ByteBuffer bytes;
	private final boolean written;
	
	private ChunkData(ByteBuffer bytes, boolean written) {
		this.bytes = bytes;
		this.written = written;
	}
	
	public ByteBuffer bytes() {
		return bytes;
	}
	
	public boolean wasWritten() {
		return written;
	}
	
}
