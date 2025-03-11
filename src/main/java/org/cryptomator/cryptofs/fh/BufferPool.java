package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptolib.api.Cryptor;

import jakarta.inject.Inject;
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
	private final Queue<WeakReference<ByteBuffer>> ciphertextBuffers = new ConcurrentLinkedQueue<>();
	private final Queue<WeakReference<ByteBuffer>> cleartextBuffers = new ConcurrentLinkedQueue<>();

	@Inject
	public BufferPool(Cryptor cryptor) {
		this.ciphertextChunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		this.cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
	}

	private Optional<ByteBuffer> dequeueFrom(Queue<WeakReference<ByteBuffer>> queue) {
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

	public ByteBuffer getCiphertextBuffer() {
		return dequeueFrom(ciphertextBuffers).orElseGet(() -> ByteBuffer.allocate(ciphertextChunkSize));
	}

	public ByteBuffer getCleartextBuffer() {
		return dequeueFrom(cleartextBuffers).orElseGet(() -> ByteBuffer.allocate(cleartextChunkSize));
	}

	public void recycle(ByteBuffer buffer) {
		if (buffer.capacity() == ciphertextChunkSize) {
			ciphertextBuffers.add(new WeakReference<>(buffer));
		} else if (buffer.capacity() == cleartextChunkSize) {
			cleartextBuffers.add(new WeakReference<>(buffer));
		}
	}
}
