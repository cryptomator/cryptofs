package org.cryptomator.cryptofs.ch;

import org.cryptomator.cryptofs.CurrentOpenFilePath;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

@ChannelScoped
class FileHeaderHandler {

	private static final Logger LOG = LoggerFactory.getLogger(FileHeaderHandler.class);

	private final FileChannel ciphertextChannel;
	private final Cryptor cryptor;
	private final EffectiveOpenOptions options;
	private final AtomicReference<Path> path;
	private final AtomicReference<FileHeader> header = new AtomicReference<>();
	private boolean isNewHeader;

	@Inject
	public FileHeaderHandler(FileChannel ciphertextChannel, Cryptor cryptor, EffectiveOpenOptions options, @CurrentOpenFilePath AtomicReference<Path> path) {
		this.ciphertextChannel = ciphertextChannel;
		this.cryptor = cryptor;
		this.options = options;
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
			if (options.truncateExisting() || options.createNew() || options.create() && ciphertextChannel.size() == 0) {
				LOG.trace("Generating file header for {}", path.get());
				isNewHeader = true;
				return cryptor.fileHeaderCryptor().create();
			} else {
				LOG.trace("Reading file header from {}", path.get());
				ByteBuffer existingHeaderBuf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
				ciphertextChannel.position(0);
				ciphertextChannel.read(existingHeaderBuf);
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
		FileHeader header = get(); // make sure to invoke get(), as this sets isNewHeader as a side effect
		if (isNewHeader) {
			LOG.trace("Writing file header to {}", path.get());
			ciphertextChannel.write(cryptor.fileHeaderCryptor().encryptHeader(header), 0);
		}
	}

}
