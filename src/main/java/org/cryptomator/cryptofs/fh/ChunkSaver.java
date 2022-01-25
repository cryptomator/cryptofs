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
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final CryptoFileSystemStats stats;
	private final BufferPool bufferPool;

	@Inject
	public ChunkSaver(Cryptor cryptor, ChunkIO ciphertext, FileHeaderHolder headerHolder, ExceptionsDuringWrite exceptionsDuringWrite, CryptoFileSystemStats stats, BufferPool bufferPool) {
		this.cryptor = cryptor;
		this.ciphertext = ciphertext;
		this.headerHolder = headerHolder;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.stats = stats;
		this.bufferPool = bufferPool;
	}

	public void save(long chunkIndex, ChunkData chunkData) throws IOException {
		if (chunkData.isDirty()) {
			long ciphertextPos = chunkIndex * cryptor.fileContentCryptor().ciphertextChunkSize() + cryptor.fileHeaderCryptor().headerSize();
			ByteBuffer cleartextBuf = chunkData.data().duplicate();
			stats.addBytesEncrypted(cleartextBuf.remaining());
			ByteBuffer ciphertextBuf = bufferPool.getCiphertextBuffer();
			try {
				cryptor.fileContentCryptor().encryptChunk(cleartextBuf, ciphertextBuf, chunkIndex, headerHolder.get());
				ciphertextBuf.flip();
				ciphertext.write(ciphertextBuf, ciphertextPos);
			} catch (IOException e) {
				exceptionsDuringWrite.add(e);
			} finally {
				bufferPool.recycle(ciphertextBuf);
			} // unchecked exceptions will be propagated to the thread causing removal
		}
	}

}
