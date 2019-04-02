package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

@OpenFileScoped
class FileHeaderHandler {

	private static final Logger LOG = LoggerFactory.getLogger(FileHeaderHandler.class);

	private final ChunkIO ciphertext;
	private final Cryptor cryptor;
	private final AtomicReference<Path> path;
	private final AtomicReference<FileHeader> header = new AtomicReference<>();
	private boolean dirty;

	@Inject
	public FileHeaderHandler(ChunkIO ciphertext, Cryptor cryptor, @CurrentOpenFilePath AtomicReference<Path> path) {
		this.ciphertext = ciphertext;
		this.cryptor = cryptor;
		this.path = path;
	}

	public FileHeader get() throws IOException {
		try {
			return header.updateAndGet(cached -> cached == null ? load() : cached);
		} catch (UncheckedIOException e) {
			throw new IOException(e);
		}
	}

	private FileHeader load() throws UncheckedIOException {
		try {
			if (ciphertext.size() == 0) { // i.e. TRUNCATE_EXISTING, CREATE OR CREATE_NEW
				LOG.trace("Generating file header for {}", path.get());
				dirty = true;
				return cryptor.fileHeaderCryptor().create();
			} else {
				LOG.trace("Reading file header from {}", path.get());
				ByteBuffer existingHeaderBuf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
				ciphertext.read(existingHeaderBuf, 0);
				existingHeaderBuf.flip();
				try {
					return cryptor.fileHeaderCryptor().decryptHeader(existingHeaderBuf);
				} catch (IllegalArgumentException | CryptoException e) {
					throw new IOException("Unable to decrypt header of file " + path.get(), e);
				}
			}
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	public void persistIfNeeded() throws IOException {
		FileHeader header = get(); // make sure to invoke get(), as this sets dirty as a side effect
		if (dirty) {
			LOG.trace("Writing file header to {}", path.get());
			ciphertext.write(cryptor.fileHeaderCryptor().encryptHeader(header), 0);
			dirty = false;
		}
	}

}
