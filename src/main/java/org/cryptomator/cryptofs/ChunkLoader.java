package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

import javax.inject.Inject;

import dagger.Lazy;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

@PerOpenFile
class ChunkLoader {

	private final Cryptor cryptor;
	private final FileChannel channel;
	private final FileHeaderLoader headerLoader;
	private final CryptoFileSystemStats stats;

	@Inject
	public ChunkLoader(Cryptor cryptor, FileChannel channel, FileHeaderLoader headerLoader, CryptoFileSystemStats stats) {
		this.cryptor = cryptor;
		this.channel = channel;
		this.headerLoader = headerLoader;
		this.stats = stats;
	}

	public ChunkData load(Long chunkIndex) throws IOException {
		stats.addChunkCacheMiss();
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
			ByteBuffer cleartextBuf = cryptor.fileContentCryptor().decryptChunk(ciphertextBuf, chunkIndex, headerLoader.get(), true);
			stats.addBytesDecrypted(cleartextBuf.remaining());
			ByteBuffer cleartextBufWhichCanHoldFullChunk;
			if (cleartextBuf.capacity() < payloadSize) {
				cleartextBufWhichCanHoldFullChunk = ByteBuffer.allocate(payloadSize);
				cleartextBufWhichCanHoldFullChunk.put(cleartextBuf);
				cleartextBufWhichCanHoldFullChunk.flip();
			} else {
				cleartextBufWhichCanHoldFullChunk = cleartextBuf;
			}
			return ChunkData.wrap(cleartextBufWhichCanHoldFullChunk);
		}
	}

}
