package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.concurrent.atomic.AtomicLong;

import javax.inject.Inject;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

@PerOpenFile
class ChunkSaver {

	private final Cryptor cryptor;
	private final FileChannel channel;
	private final FileHeader header;
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final AtomicLong size;
	private final CryptoFileSystemStats stats;

	@Inject
	public ChunkSaver(Cryptor cryptor, FileChannel channel, FileHeader header, ExceptionsDuringWrite exceptionsDuringWrite, @OpenFileSize AtomicLong size, CryptoFileSystemStats stats) {
		this.cryptor = cryptor;
		this.channel = channel;
		this.header = header;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.size = size;
		this.stats = stats;
	}

	public void save(long chunkIndex, ChunkData chunkData) {
		if (chunkLiesInFile(chunkIndex) && chunkData.wasWritten()) {
			long ciphertextPos = chunkIndex * cryptor.fileContentCryptor().ciphertextChunkSize() + cryptor.fileHeaderCryptor().headerSize();
			ByteBuffer cleartextBuf = chunkData.asReadOnlyBuffer();
			stats.addBytesEncrypted(cleartextBuf.remaining());
			ByteBuffer ciphertextBuf = cryptor.fileContentCryptor().encryptChunk(cleartextBuf, chunkIndex, header);
			try {
				channel.write(ciphertextBuf, ciphertextPos);
			} catch (IOException e) {
				exceptionsDuringWrite.add(e);
			} // unchecked exceptions will be propagated to the thread causing removal
		}
	}

	private boolean chunkLiesInFile(long chunkIndex) {
		return chunkIndex * cryptor.fileContentCryptor().cleartextChunkSize() < size.get();
	}

}
