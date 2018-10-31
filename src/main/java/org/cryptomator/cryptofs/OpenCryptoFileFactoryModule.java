/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs;

import dagger.Module;
import dagger.Provides;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.util.concurrent.atomic.AtomicLong;

import static org.cryptomator.cryptofs.UncheckedThrows.rethrowUnchecked;
import static org.cryptomator.cryptolib.Cryptors.cleartextSize;

@Module
class OpenCryptoFileFactoryModule {

	@Provides
	@PerOpenFile
	public FileChannel provideFileChannel(@OriginalOpenFilePath Path path, EffectiveOpenOptions options) {
		return rethrowUnchecked(IOException.class).from(() -> path.getFileSystem().provider().newFileChannel(path, options.createOpenOptionsForEncryptedFile()));
	}

	@Provides
	@PerOpenFile
	public BasicFileAttributeView provideBasicFileAttributeView(@OriginalOpenFilePath Path path) {
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

}
