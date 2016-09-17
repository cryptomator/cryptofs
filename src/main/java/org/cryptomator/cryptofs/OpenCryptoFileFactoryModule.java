package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.UncheckedThrows.rethrowUnchecked;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicLong;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

import dagger.Module;
import dagger.Provides;

@Module
class OpenCryptoFileFactoryModule {

	@Provides
	@PerOpenFile
	public FileChannel provideFileChannel(@OpenFilePath Path path, EffectiveOpenOptions options) {
		return rethrowUnchecked(IOException.class).from(() -> path.getFileSystem().provider().newFileChannel(path, options.createOpenOptionsForEncryptedFile()));
	}

	@Provides
	@PerOpenFile
	@OpenFileSize
	public AtomicLong provideFileSize() {
		return new AtomicLong();
	}

	@Provides
	@PerOpenFile
	public FileHeader provideFileHader(FileChannel channel, Cryptor cryptor, EffectiveOpenOptions options) {
		return rethrowUnchecked(IOException.class).from(() -> {
			if (options.truncateExisting() || isNewFile(channel, options)) {
				return cryptor.fileHeaderCryptor().create();
			} else {
				ByteBuffer existingHeaderBuf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
				channel.position(0);
				channel.read(existingHeaderBuf);
				existingHeaderBuf.flip();
				return cryptor.fileHeaderCryptor().decryptHeader(existingHeaderBuf);
			}
		});
	}

	private boolean isNewFile(FileChannel channel, EffectiveOpenOptions options) throws IOException {
		return options.createNew() || options.create() && channel.size() == 0;
	}

}
