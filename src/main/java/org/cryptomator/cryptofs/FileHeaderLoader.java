package org.cryptomator.cryptofs;

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

@PerOpenFile
class FileHeaderLoader {

	private static final Logger LOG = LoggerFactory.getLogger(FileHeaderLoader.class);

	private final FileChannel channel;
	private final Cryptor cryptor;
	private final EffectiveOpenOptions options;
	private final AtomicReference<Path> path;

	private final AtomicReference<FileHeader> header = new AtomicReference<>();

	@Inject
	public FileHeaderLoader(FileChannel channel, Cryptor cryptor, EffectiveOpenOptions options, @CurrentOpenFilePath AtomicReference<Path> path) {
		this.channel = channel;
		this.cryptor = cryptor;
		this.options = options;
		this.path = path;
	}

	public FileHeader get() throws IOException {
		try {
			return header.updateAndGet(cached -> cached == null ? load() : cached);
		} catch (UncheckedIOException e) {
			throw e.getCause();
		}
	}

	private FileHeader load() throws UncheckedIOException {
		try {
			if (options.truncateExisting() || isNewFile(channel, options)) {
				LOG.trace("Generating file header for {}", path.get());
				return cryptor.fileHeaderCryptor().create();
			} else {
				LOG.trace("Reading file header from {}", path.get());
				ByteBuffer existingHeaderBuf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
				channel.position(0);
				channel.read(existingHeaderBuf);
				existingHeaderBuf.flip();
				try {
					return cryptor.fileHeaderCryptor().decryptHeader(existingHeaderBuf);
				} catch (IllegalArgumentException e) {
					throw new IOException(e);
				}
			}
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private boolean isNewFile(FileChannel channel, EffectiveOpenOptions options) throws IOException {
		return options.createNew() || options.create() && channel.size() == 0;
	}


}
