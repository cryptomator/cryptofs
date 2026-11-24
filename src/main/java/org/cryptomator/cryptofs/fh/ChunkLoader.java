package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptofs.event.DecryptionFailedEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.function.Consumer;

@OpenFileScoped
class ChunkLoader {

	private final Consumer<FilesystemEvent> eventConsumer;
	private final Cryptor cryptor;
	private final ChunkIO ciphertext;
	private final FileHeaderHolder headerHolder;
	private final CryptoFileSystemStats stats;
	private final BufferPool bufferPool;
	private final CiphertextWriteGuard writeGuard;

	@Inject
	public ChunkLoader(Consumer<FilesystemEvent> eventConsumer, Cryptor cryptor, ChunkIO ciphertext, FileHeaderHolder headerHolder, CryptoFileSystemStats stats, BufferPool bufferPool, CiphertextWriteGuard writeGuard) {
		this.eventConsumer = eventConsumer;
		this.cryptor = cryptor;
		this.ciphertext = ciphertext;
		this.headerHolder = headerHolder;
		this.stats = stats;
		this.bufferPool = bufferPool;
		this.writeGuard = writeGuard;
	}

	public ByteBuffer load(Long chunkIndex) throws IOException, AuthenticationFailedException {
		int chunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		long ciphertextPos = chunkIndex * chunkSize + cryptor.fileHeaderCryptor().headerSize();
		ByteBuffer ciphertextBuf = bufferPool.getCiphertextBuffer();
		ByteBuffer cleartextBuf = bufferPool.getCleartextBuffer();
		try {
			int read = readFully(ciphertextBuf, ciphertextPos);
			if (read <= chunkSize - cryptor.fileContentCryptor().cleartextChunkSize()) { // nothing here, or a remainder too short to hold a chunk
				cleartextBuf.limit(0);
				writeGuard.observe(chunkIndex, ciphertextBuf.flip());
			} else {
				ciphertextBuf.flip();
				ByteBuffer loadedCiphertext = ciphertextBuf.duplicate();
				cryptor.fileContentCryptor().decryptChunk(ciphertextBuf, cleartextBuf, chunkIndex, headerHolder.get(), true);
				writeGuard.observe(chunkIndex, loadedCiphertext);
				cleartextBuf.flip();
				stats.addBytesDecrypted(cleartextBuf.remaining());
			}
			return cleartextBuf;
		} catch (AuthenticationFailedException e) {
			var event = new DecryptionFailedEvent(writeGuard.ciphertextPath(), e);
			Thread.ofVirtual().name("cryptofs-decryption-event").start(() -> eventConsumer.accept(event)); // this thread holds locks a consumer touching this file would wait for
			throw e;
		} finally {
			bufferPool.recycle(ciphertextBuf);
		}
	}

	private int readFully(ByteBuffer dst, long position) throws IOException {
		while (dst.hasRemaining() && ciphertext.read(dst, position + dst.position()) > 0) {
			// a short read is not the end of the file
		}
		return dst.position();
	}

}
