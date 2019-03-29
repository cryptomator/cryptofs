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
	private final FileHeaderHandler headerHandler;
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final CryptoFileSystemStats stats;

	@Inject
	public ChunkSaver(Cryptor cryptor, ChunkIO ciphertext, FileHeaderHandler headerHandler, ExceptionsDuringWrite exceptionsDuringWrite, CryptoFileSystemStats stats) {
		this.cryptor = cryptor;
		this.ciphertext = ciphertext;
		this.headerHandler = headerHandler;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.stats = stats;
	}

	public void save(long chunkIndex, ChunkData chunkData) throws IOException {
		if (chunkData.isDirty()) {
			long ciphertextPos = chunkIndex * cryptor.fileContentCryptor().ciphertextChunkSize() + cryptor.fileHeaderCryptor().headerSize();
			ByteBuffer cleartextBuf = chunkData.asReadOnlyBuffer();
			stats.addBytesEncrypted(cleartextBuf.remaining());
			ByteBuffer ciphertextBuf = cryptor.fileContentCryptor().encryptChunk(cleartextBuf, chunkIndex, headerHandler.get());
			try {
				headerHandler.persistIfNeeded();
				ciphertext.write(ciphertextBuf, ciphertextPos);
			} catch (IOException e) {
				exceptionsDuringWrite.add(e);
			} // unchecked exceptions will be propagated to the thread causing removal
		}
	}

}
