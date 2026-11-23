package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@OpenFileScoped
public class FileHeaderHolder {

	private static final Logger LOG = LoggerFactory.getLogger(FileHeaderHolder.class);

	private final Cryptor cryptor;
	private final AtomicReference<Path> path;
	private final AtomicReference<FileHeader> header = new AtomicReference<>();
	private final AtomicReference<ByteBuffer> encryptedHeader = new AtomicReference<>();
	private final AtomicBoolean isPersisted = new AtomicBoolean();

	@Inject
	public FileHeaderHolder(Cryptor cryptor, @CurrentOpenFilePath AtomicReference<Path> path) {
		this.cryptor = cryptor;
		this.path = path;
	}

	public FileHeader get() {
		FileHeader result = header.get();
		if (result == null) {
			throw new IllegalStateException("Header not set.");
		}
		return result;
	}

	public ByteBuffer getEncrypted() {
		var result = encryptedHeader.get();
		if (result == null) {
			throw new IllegalStateException("Header not set.");
		}
		return result;
	}

	FileHeader createNew() {
		LOG.trace("Generating file header for {}", path.get());
		FileHeader newHeader = cryptor.fileHeaderCryptor().create();
		encryptedHeader.set(cryptor.fileHeaderCryptor().encryptHeader(newHeader).asReadOnlyBuffer()); //to prevent NONCE reuse, we already encrypt the header and cache it
		header.set(newHeader);
		return newHeader;
	}


	/**
	 * Reads, decrypts and caches the file header from the given file channel.
	 *
	 * @param ch File channel to the encrypted file
	 * @return {@link FileHeader} of the encrypted file
	 * @throws IOException if the file header cannot be read or decrypted
	 */
	FileHeader loadExisting(FileChannel ch) throws IOException {
		LOG.trace("Reading file header from {}", path.get());
		ByteBuffer existingHeaderBuf = readHeaderBytes(ch);
		try {
			FileHeader existingHeader = cryptor.fileHeaderCryptor().decryptHeader(existingHeaderBuf);
			encryptedHeader.set(existingHeaderBuf.rewind().asReadOnlyBuffer()); //for consistency
			header.set(existingHeader);
			isPersisted.set(true);
			return existingHeader;
		} catch (IllegalArgumentException | CryptoException e) {
			throw new HeaderDecryptionException(path.get(), e);
		}
	}

	/**
	 * Checks whether the file of the given channel starts with this header, as far as its bytes are present.
	 * A header that isn't persisted yet may be absent or partially written, but a persisted header must be complete.
	 *
	 * @param ch File channel to an encrypted file
	 * @return <code>false</code> if the file holds another header, or is shorter than a persisted header
	 * @throws IOException if the file header cannot be read
	 */
	boolean isHeaderOf(FileChannel ch) throws IOException {
		boolean persisted = isPersisted.get(); // sample before reading, as the header gets written before the flag is set
		ByteBuffer actual = readHeaderBytes(ch);
		if (persisted && actual.remaining() < cryptor.fileHeaderCryptor().headerSize()) {
			return false;
		}
		ByteBuffer expected = getEncrypted().duplicate().rewind();
		expected.limit(Math.min(expected.limit(), actual.remaining()));
		return actual.equals(expected);
	}

	private ByteBuffer readHeaderBytes(FileChannel ch) throws IOException {
		ByteBuffer buf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
		int read;
		do {
			read = ch.read(buf, buf.position());
		} while (read > 0 && buf.hasRemaining());
		return buf.flip();
	}

	public AtomicBoolean headerIsPersisted() {
		return isPersisted;
	}

}
