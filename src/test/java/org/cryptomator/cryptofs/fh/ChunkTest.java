package org.cryptomator.cryptofs.fh;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.LongAdder;

import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;

public class ChunkTest {

	@Test // https://github.com/cryptomator/cryptofs/issues/85
	public void testRaceConditionsDuringRead() {
		ByteBuffer src = StandardCharsets.US_ASCII.encode("abcdefg");
		Chunk inTest = new Chunk(src, false, () -> {});
		int attempts = 4000;
		int threads = 6;

		CountDownLatch cdl = new CountDownLatch(attempts);
		ExecutorService executor = Executors.newFixedThreadPool(threads);
		LongAdder successfulTests = new LongAdder();

		for (int i = 0; i < attempts; i++) {
			int offset = i % 7;
			char expected = "abcdefg".charAt(offset);
			executor.execute(() -> {
				try {
					ByteBuffer dst = ByteBuffer.allocate(1);
					dst.put(0, inTest.data(), offset, 1);
					char actual = StandardCharsets.US_ASCII.decode(dst).charAt(0);
					if (expected == actual) {
						successfulTests.increment();
					}
				} finally {
					cdl.countDown();
				}
			});
		}

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> cdl.await());
		Assertions.assertEquals(attempts, successfulTests.sum());
	}

}
