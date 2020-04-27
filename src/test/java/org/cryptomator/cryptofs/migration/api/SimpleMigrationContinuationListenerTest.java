package org.cryptomator.cryptofs.migration.api;

import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener.ContinuationEvent;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener.ContinuationResult;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

class SimpleMigrationContinuationListenerTest {
	
	@Test
	public void testConcurrency() {
		ExecutorService threadPool = Executors.newFixedThreadPool(1);
		Lock lock = new ReentrantLock();
		Condition receivedEvent = lock.newCondition();

		SimpleMigrationContinuationListener inTest = new SimpleMigrationContinuationListener() {
			@Override
			void migrationHaltedDueToEvent(ContinuationEvent event) {
				System.out.println("received event on " + Thread.currentThread());
				lock.lock();
				try {
					receivedEvent.signal();
				} finally {
					lock.unlock();
				}
			}
		};

		threadPool.submit(() -> {
			lock.lock();
			try {
				receivedEvent.await();
				System.out.println("choosing PROCEED on thread " + Thread.currentThread());
				inTest.continueMigrationWithResult(ContinuationResult.PROCEED);
			} catch (InterruptedException e) {
				Thread.interrupted();
				Assertions.fail();
			} finally {
				lock.unlock();
			}
		});

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(1), () -> { // deadlock protection
			ContinuationResult result = inTest.continueMigrationOnEvent(ContinuationEvent.REQUIRES_FULL_VAULT_DIR_SCAN);
			Assertions.assertEquals(ContinuationResult.PROCEED, result);
		});
	}

}