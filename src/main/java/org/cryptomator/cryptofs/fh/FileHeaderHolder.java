package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

@OpenFileScoped
public class FileHeaderHolder {

	private static final Logger LOG = LoggerFactory.getLogger(FileHeaderHolder.class);

	private final Cryptor cryptor;
	private final AtomicReference<Path> path;
	private final AtomicReference<FileHeader> header = new AtomicReference<>();

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

	public FileHeader createNew() {
		LOG.trace("Generating file header for {}", path.get());
		FileHeader newHeader = cryptor.fileHeaderCryptor().create();
		if (header.compareAndSet(null, newHeader)) {
			return newHeader;
		} else {
			return header.get();
		}
	}

	public FileHeader loadExisting(FileChannel ch) throws IOException {
		LOG.trace("Reading file header from {}", path.get());
		ByteBuffer existingHeaderBuf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
		int read = ch.read(existingHeaderBuf, 0);
		assert read == existingHeaderBuf.capacity();
		existingHeaderBuf.flip();
		try {
			FileHeader existingHeader = cryptor.fileHeaderCryptor().decryptHeader(existingHeaderBuf);
			header.set(existingHeader);
			return existingHeader;
		} catch (IllegalArgumentException | CryptoException e) {
			throw new IOException("Unable to decrypt header of file " + path.get(), e);
		}
	}

}
