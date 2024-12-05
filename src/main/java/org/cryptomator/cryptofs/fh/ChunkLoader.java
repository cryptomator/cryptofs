package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptofs.event.DecryptionFailedEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

@OpenFileScoped
class ChunkLoader {

	private final Consumer<FilesystemEvent> observer;
	private final AtomicReference<Path> path;
	private final Cryptor cryptor;
	private final ChunkIO ciphertext;
	private final FileHeaderHolder headerHolder;
	private final CryptoFileSystemStats stats;
	private final BufferPool bufferPool;

	@Inject
	public ChunkLoader(@Named("Babadook") Consumer<FilesystemEvent> observer, @CurrentOpenFilePath AtomicReference<Path> path, Cryptor cryptor, ChunkIO ciphertext, FileHeaderHolder headerHolder, CryptoFileSystemStats stats, BufferPool bufferPool) {
		this.observer = observer;
		this.path = path;
		this.cryptor = cryptor;
		this.ciphertext = ciphertext;
		this.headerHolder = headerHolder;
		this.stats = stats;
		this.bufferPool = bufferPool;
	}

	public ByteBuffer load(Long chunkIndex) throws IOException, AuthenticationFailedException {
		int chunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		long ciphertextPos = chunkIndex * chunkSize + cryptor.fileHeaderCryptor().headerSize();
		ByteBuffer ciphertextBuf = bufferPool.getCiphertextBuffer();
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
		} catch (AuthenticationFailedException e) {
			observer.accept(new DecryptionFailedEvent(path.get(), e));
			throw e;
		} finally {
			bufferPool.recycle(ciphertextBuf);
		}
	}

}
