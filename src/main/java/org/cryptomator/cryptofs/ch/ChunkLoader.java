package org.cryptomator.cryptofs.ch;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

@ChannelScoped
class ChunkLoader {

	private final Cryptor cryptor;
	private final FileChannel channel;
	private final FileHeaderHandler headerHandler;
	private final CryptoFileSystemStats stats;

	@Inject
	public ChunkLoader(Cryptor cryptor, FileChannel channel, FileHeaderHandler headerHandler, CryptoFileSystemStats stats) {
		this.cryptor = cryptor;
		this.channel = channel;
		this.headerHandler = headerHandler;
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
			ByteBuffer cleartextBuf = cryptor.fileContentCryptor().decryptChunk(ciphertextBuf, chunkIndex, headerHandler.get(), true);
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
