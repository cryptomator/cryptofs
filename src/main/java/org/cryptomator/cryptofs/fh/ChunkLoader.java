package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
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
	private final BufferPool bufferPool;

	@Inject
	public ChunkLoader(Cryptor cryptor, ChunkIO ciphertext, FileHeaderHolder headerHolder, CryptoFileSystemStats stats, BufferPool bufferPool) {
		this.cryptor = cryptor;
		this.ciphertext = ciphertext;
		this.headerHolder = headerHolder;
		this.stats = stats;
		this.bufferPool = bufferPool;
	}

	public ByteBuffer load(Long chunkIndex) throws IOException, AuthenticationFailedException {
		stats.addChunkCacheMiss();
		int chunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		long ciphertextPos = chunkIndex * chunkSize + cryptor.fileHeaderCryptor().headerSize();
		//ByteBuffer ciphertextBuf = ByteBuffer.allocate(cryptor.fileContentCryptor().ciphertextChunkSize());
		ByteBuffer ciphertextBuf = bufferPool.getCiphertextBuffer();
		//ByteBuffer cleartextBuf = ByteBuffer.allocate(cryptor.fileContentCryptor().cleartextChunkSize());
		ByteBuffer cleartextBuf = bufferPool.getCleartextBuffer();
		try {
			int read = ciphertext.read(ciphertextBuf, ciphertextPos);
			if (read == -1) {
				cleartextBuf.limit(0);
			} else {
				ciphertextBuf.flip();
				cryptor.fileContentCryptor().decryptChunk(ciphertextBuf, cleartextBuf, chunkIndex, headerHolder.get(), true);
				cleartextBuf.flip();
				stats.addBytesDecrypted(cleartextBuf.remaining());
			}
			return cleartextBuf;
		} finally {
			bufferPool.recycle(ciphertextBuf);
		}
	}

}
