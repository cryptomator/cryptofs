package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;

@OpenFileScoped
class ChunkSaver {

	private final Cryptor cryptor;
	private final ChunkIO ciphertext;
	private final FileHeaderHolder headerHolder;
	private final CryptoFileSystemStats stats;
	private final BufferPool bufferPool;

	@Inject
	public ChunkSaver(Cryptor cryptor, ChunkIO ciphertext, FileHeaderHolder headerHolder, CryptoFileSystemStats stats, BufferPool bufferPool) {
		this.cryptor = cryptor;
		this.ciphertext = ciphertext;
		this.headerHolder = headerHolder;
		this.stats = stats;
		this.bufferPool = bufferPool;
	}

	public void save(long chunkIndex, Chunk chunkData) throws IOException {
		if (chunkData.isDirty()) {
			long ciphertextPos = chunkIndex * cryptor.fileContentCryptor().ciphertextChunkSize() + cryptor.fileHeaderCryptor().headerSize();
			ByteBuffer cleartextBuf = chunkData.data().asReadOnlyBuffer();
			stats.addBytesEncrypted(cleartextBuf.remaining());
			ByteBuffer ciphertextBuf = bufferPool.getCiphertextBuffer();
			try {
				cryptor.fileContentCryptor().encryptChunk(cleartextBuf, ciphertextBuf, chunkIndex, headerHolder.get());
				ciphertextBuf.flip();
				ciphertext.write(ciphertextBuf, ciphertextPos);
				chunkData.dirty().set(false);
			} finally {
				bufferPool.recycle(ciphertextBuf);
			}
		}
	}

}
