package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

import javax.inject.Inject;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

@PerOpenFile
class ChunkLoader {

	private final Cryptor cryptor;
	private final FileChannel channel;
	private final FileHeader header;

	@Inject
	public ChunkLoader(Cryptor cryptor, FileChannel channel, FileHeader header) {
		this.cryptor = cryptor;
		this.channel = channel;
		this.header = header;
	}

	public ChunkData load(Long chunkIndex) throws IOException {
		int payloadSize = cryptor.fileContentCryptor().cleartextChunkSize();
		int chunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		long ciphertextPos = chunkIndex * chunkSize + cryptor.fileHeaderCryptor().headerSize();
		ByteBuffer ciphertextBuf = ByteBuffer.allocate(chunkSize);
		int read = channel.read(ciphertextBuf, ciphertextPos);
		if (read == -1) {
			// append
			return ChunkData.emptyWithSize(payloadSize);
		} else {
			ciphertextBuf.flip();
			return ChunkData.wrap(cryptor.fileContentCryptor().decryptChunk(ciphertextBuf, chunkIndex, header, true));
		}
	}

}
