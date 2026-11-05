package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemStats;
import org.cryptomator.cryptolib.api.Cryptor;

import jakarta.inject.Inject;
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

	/**
	 * Encrypts the given chunk, if it is dirty, and writes it to its position in the ciphertext file.
	 * <p>
	 * The write position is derived from the chunk index and the header size; the chunk index is also part of the
	 * authenticated associated data, so it must be the index the chunk was decrypted with.
	 *
	 * @param chunkIndex index of the chunk within the cleartext file
	 * @param chunkData  the chunk to persist; untouched (and left dirty) if the write does not complete
	 * @throws IOException if the ciphertext cannot be written completely, e.g. because the channel stops accepting bytes
	 */
	public void save(long chunkIndex, Chunk chunkData) throws IOException {
		if (chunkData.isDirty()) {
			long ciphertextPos = chunkIndex * cryptor.fileContentCryptor().ciphertextChunkSize() + cryptor.fileHeaderCryptor().headerSize();
			// Do NOT wrap this in asReadOnlyBuffer(): a read-only buffer has hasArray()==false and makes JCE copy the
			// input instead of using its heap fast path (~2x slower GCM). JCE never modifies the source buffer.
			ByteBuffer cleartextBuf = chunkData.data().duplicate();
			stats.addBytesEncrypted(cleartextBuf.remaining());
			ByteBuffer ciphertextBuf = bufferPool.getCiphertextBuffer();
			try {
				cryptor.fileContentCryptor().encryptChunk(cleartextBuf, ciphertextBuf, chunkIndex, headerHolder.get());
				ciphertextBuf.flip();
				writeFully(ciphertextBuf, ciphertextPos);
				chunkData.dirty().set(false); // only after ALL bytes hit the channel, otherwise the chunk would be lost silently
			} finally {
				bufferPool.recycle(ciphertextBuf);
			}
		}
	}

	/**
	 * {@link java.nio.channels.FileChannel#write(ByteBuffer, long)} may write fewer bytes than requested. Treating a short
	 * write as success would leave a torn ciphertext chunk behind and mark it clean.
	 */
	private void writeFully(ByteBuffer src, long position) throws IOException {
		while (src.hasRemaining()) {
			int written = ciphertext.write(src, position);
			if (written <= 0) {
				throw new IOException("Unable to make progress while writing ciphertext chunk at position " + position);
			}
			position += written;
		}
	}

}
