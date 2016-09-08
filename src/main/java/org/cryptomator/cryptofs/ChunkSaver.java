package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.concurrent.atomic.AtomicLong;

import javax.inject.Inject;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

@PerOpenFile
class ChunkSaver implements RemovalListener<Long, ChunkData> {

	private final Cryptor cryptor;
	private final FileChannel channel;
	private final FileHeader header;
	private final ExceptionsDuringWrite exceptionsDuringWrite;
	private final AtomicLong size;

	@Inject
	public ChunkSaver(Cryptor cryptor, FileChannel channel, FileHeader header, ExceptionsDuringWrite exceptionsDuringWrite, @OpenFileSize AtomicLong size) {
		this.cryptor = cryptor;
		this.channel = channel;
		this.header = header;
		this.exceptionsDuringWrite = exceptionsDuringWrite;
		this.size = size;
	}

	@Override
	public void onRemoval(RemovalNotification<Long, ChunkData> notification) {
		onRemoval(notification.getKey(), notification.getValue());
	}

	private void onRemoval(long chunkIndex, ChunkData chunkData) {
		if (chunkLiesInFile(chunkIndex) && chunkData.wasWritten()) {
			long ciphertextPos = chunkIndex * cryptor.fileContentCryptor().ciphertextChunkSize() + cryptor.fileHeaderCryptor().headerSize();
			ByteBuffer cleartextBuf = chunkData.asReadOnlyBuffer();
			// TODO write only part of chunk that lies in file, or is this handled by encryptChunk?
			ByteBuffer ciphertextBuf = cryptor.fileContentCryptor().encryptChunk(cleartextBuf, chunkIndex, header);
			try {
				channel.write(ciphertextBuf, ciphertextPos);
			} catch (IOException e) {
				exceptionsDuringWrite.add(e);
			} // unchecked exceptions will be propagated to the thread causing removal
		}
	}

	private boolean chunkLiesInFile(long chunkIndex) {
		return chunkIndex * cryptor.fileContentCryptor().cleartextChunkSize() < size.get();
	}

}
