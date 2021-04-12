package org.cryptomator.cryptofs.health.api;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

class TransferSpliteratorTest {

	private ExecutorService executor;

	@BeforeEach
	public void setup() {
		executor = Executors.newCachedThreadPool();
	}

	@AfterEach
	public void teardown() {
		executor.shutdown();
	}

	@RepeatedTest(100)
	@DisplayName("spliterator terminates after reading all results")
	public void testTerminatesWhenClosed() {
		TransferSpliterator<String> transferSpliterator = new TransferSpliterator<>("POISON");
		executor.submit(() -> {
			try {
				transferSpliterator.accept("one");
				transferSpliterator.accept("two");
				transferSpliterator.accept("three");
			} finally {
				transferSpliterator.close();
			}
		});

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
			Assertions.assertTrue(transferSpliterator.tryAdvance(s -> Assertions.assertEquals("one", s)));
			Assertions.assertTrue(transferSpliterator.tryAdvance(s -> Assertions.assertEquals("two", s)));
			Assertions.assertTrue(transferSpliterator.tryAdvance(s -> Assertions.assertEquals("three", s)));
			Assertions.assertFalse(transferSpliterator.tryAdvance(s -> {}));
		});
	}

	@Test
	@DisplayName("constructor rejects null poison")
	public void testFailOnNullPoison() {
		Assertions.assertThrows(NullPointerException.class, () -> {
			new TransferSpliterator<>(null);
		});
	}

	@Test
	@DisplayName("spliterator throws exception when attempting to transfer after close()")
	public void testDoesNotAcceptAfterClose() {
		TransferSpliterator<String> transferSpliterator = new TransferSpliterator<>("POISON");
		transferSpliterator.close();
		Assertions.assertThrows(TransferSpliterator.TransferClosedException.class, () -> {
			transferSpliterator.accept("one");
		});
	}

	@RepeatedTest(100)
	@DisplayName("spliterator handles interrupt gracefully")
	public void testHandleInterruptGracefully() {
		TransferSpliterator<String> transferSpliterator = new TransferSpliterator<>("POISON");
		CountDownLatch cdl1 = new CountDownLatch(1);
		CountDownLatch cdl2 = new CountDownLatch(1);
		Future<?> task = executor.submit(() -> {
			try {
				transferSpliterator.accept("one");
				cdl1.countDown();
				transferSpliterator.accept("two"); // will be cancelled by interrupt
				transferSpliterator.accept("three");
			} catch (TransferSpliterator.TransferClosedException e) {
				cdl2.countDown();
			} finally {
				transferSpliterator.close();
			}
		});

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
			Assertions.assertTrue(transferSpliterator.tryAdvance(s -> Assertions.assertEquals("one", s)));
			cdl1.await();
			task.cancel(true);
			cdl2.await();
			Assertions.assertFalse(transferSpliterator.tryAdvance(s -> {}));
		});
	}

}