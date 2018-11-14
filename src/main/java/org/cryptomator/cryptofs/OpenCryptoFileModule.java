package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import dagger.Module;
import dagger.Provides;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

import static org.cryptomator.cryptofs.UncheckedThrows.rethrowUnchecked;
import static org.cryptomator.cryptolib.Cryptors.cleartextSize;

@Module
class OpenCryptoFileModule {

	private final Path originalPath;
	private final AtomicReference<Path> currentPath;
	private final EffectiveOpenOptions options;

	private OpenCryptoFileModule(Builder builder) {
		this.originalPath = builder.path;
		this.currentPath = new AtomicReference<>(builder.path);
		this.options = builder.options;
	}

	@Provides
	@PerOpenFile
	@OriginalOpenFilePath
	public Path provideOriginalPath() {
		return originalPath;
	}

	@Provides
	@PerOpenFile
	@CurrentOpenFilePath
	public AtomicReference<Path> provideCurrentPath() {
		return currentPath;
	}

	@Provides
	@PerOpenFile
	public EffectiveOpenOptions provideOptions() {
		return options;
	}

	@Provides
	@PerOpenFile
	public FileChannel provideFileChannel(EffectiveOpenOptions options) {
		return rethrowUnchecked(IOException.class).from(() -> originalPath.getFileSystem().provider().newFileChannel(originalPath, options.createOpenOptionsForEncryptedFile()));
	}

	@Provides
	@PerOpenFile
	public BasicFileAttributeView provideBasicFileAttributeView() {
		Path path = currentPath.get();
		return path.getFileSystem().provider().getFileAttributeView(path, BasicFileAttributeView.class);
	}

	@Provides
	@PerOpenFile
	@OpenFileSize
	public AtomicLong provideFileSize(FileChannel channel, Cryptor cryptor) {
		return rethrowUnchecked(IOException.class).from(() -> {
			long size = channel.size();
			if (size == 0) {
				return new AtomicLong();
			} else {
				int headerSize = cryptor.fileHeaderCryptor().headerSize();
				return new AtomicLong(cleartextSize(size - headerSize, cryptor));
			}
		});
	}

	@Provides
	@PerOpenFile
	public FileHeader provideFileHeader(FileChannel channel, Cryptor cryptor, EffectiveOpenOptions options) {
		return rethrowUnchecked(IOException.class).from(() -> {
			if (options.truncateExisting() || isNewFile(channel, options)) {
				FileHeader newHeader = cryptor.fileHeaderCryptor().create();
				channel.position(0);
				channel.write(cryptor.fileHeaderCryptor().encryptHeader(newHeader));
				channel.force(false);
				return newHeader;
			} else {
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
		});
	}

	private boolean isNewFile(FileChannel channel, EffectiveOpenOptions options) throws IOException {
		return options.createNew() || options.create() && channel.size() == 0;
	}

	public static Builder openCryptoFileModule() {
		return new Builder();
	}

	public static class Builder {

		private Path path;
		private EffectiveOpenOptions options;

		private Builder() {
		}

		public Builder withPath(Path path) {
			this.path = path;
			return this;
		}

		public Builder withOptions(EffectiveOpenOptions options) {
			this.options = options;
			return this;
		}

		public OpenCryptoFileModule build() {
			validate();
			return new OpenCryptoFileModule(this);
		}

		private void validate() {
			if (path == null) {
				throw new IllegalStateException("path must be set");
			}
			if (options == null) {
				throw new IllegalStateException("options must be set");
			}
		}

	}

}
