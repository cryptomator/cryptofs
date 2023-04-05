package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;
import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * A pool of ByteBuffers for cleartext and ciphertext chunks to avoid on-heap allocation.
 */
@CryptoFileSystemScoped
public class BufferPool {

	private final int ciphertextChunkSize;
	private final int cleartextChunkSize;
	private final BufferQueue ciphertextBuffers;
	private final BufferQueue cleartextBuffers;

	@Inject
	public BufferPool(Cryptor cryptor) {
		this.ciphertextChunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		this.cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
		this.ciphertextBuffers = new BufferQueue();
		this.cleartextBuffers = new BufferQueue();
	}

	public ByteBuffer getCiphertextBuffer() {
		return ciphertextBuffers.dequeue().orElseGet(() -> ByteBuffer.allocate(ciphertextChunkSize));
	}

	public ByteBuffer getCleartextBuffer() {
		return cleartextBuffers.dequeue().orElseGet(() -> ByteBuffer.allocate(cleartextChunkSize));
	}

	public void recycle(ByteBuffer buffer) {
		if (buffer.capacity() == ciphertextChunkSize) {
			ciphertextBuffers.enqueue(buffer);
		} else if (buffer.capacity() == cleartextChunkSize) {
			cleartextBuffers.enqueue(buffer);
		}
	}

	private static class BufferQueue {
		private final Queue<WeakReference<ByteBuffer>> queue = new ConcurrentLinkedQueue<>();

		Optional<ByteBuffer> dequeue() {
			WeakReference<ByteBuffer> ref;
			while ((ref = queue.poll()) != null) {
				ByteBuffer cached = ref.get();
				if (cached != null) {
					cached.clear();
					return Optional.of(cached);
				}
			}
			return Optional.empty();
		}

		void enqueue(ByteBuffer buffer) {
			queue.add(new WeakReference<>(buffer));
		}
	}
}
