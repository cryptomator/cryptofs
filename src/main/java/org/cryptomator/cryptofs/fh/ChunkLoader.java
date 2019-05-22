package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;

@OpenFileScoped
class ChunkLoader {

	private final Cryptor cryptor;
	private final ChunkIO ciphertext;
	private final FileHeaderHolder headerHolder;
	private final CryptoFileSystemStats stats;

	@Inject
	public ChunkLoader(Cryptor cryptor, ChunkIO ciphertext, FileHeaderHolder headerHolder, CryptoFileSystemStats stats) {
		this.cryptor = cryptor;
		this.ciphertext = ciphertext;
		this.headerHolder = headerHolder;
		this.stats = stats;
	}

	public ChunkData load(Long chunkIndex) throws IOException {
		stats.addChunkCacheMiss();
		int payloadSize = cryptor.fileContentCryptor().cleartextChunkSize();
		int chunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		long ciphertextPos = chunkIndex * chunkSize + cryptor.fileHeaderCryptor().headerSize();
		ByteBuffer ciphertextBuf = ByteBuffer.allocate(chunkSize);
		int read = ciphertext.read(ciphertextBuf, ciphertextPos);
		if (read == -1) {
			// append
			return ChunkData.emptyWithSize(payloadSize);
		} else {
			ciphertextBuf.flip();
			ByteBuffer cleartextBuf = cryptor.fileContentCryptor().decryptChunk(ciphertextBuf, chunkIndex, headerHolder.get(), true);
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
