package org.cryptomator.cryptofs.migration.api;

import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener.ContinuationEvent;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener.ContinuationResult;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class SimpleMigrationContinuationListenerTest {
	
	@Test
	public void testConcurrency() {
		ExecutorService threadPool = Executors.newCachedThreadPool();

		SimpleMigrationContinuationListener inTest = new SimpleMigrationContinuationListener() {
			@Override
			public void migrationHaltedDueToEvent(ContinuationEvent event) {
				// receive event on background thread that runs migration:
				System.out.println("received event on " + Thread.currentThread().getName());
				
				threadPool.submit(() -> {
					// choose PROCEED on different thread (like from UI events):
					System.out.println("choosing PROCEED on thread " + Thread.currentThread().getName());
					this.continueMigrationWithResult(ContinuationResult.PROCEED);
				});
			}
		};

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(10), () -> { // deadlock protection
			ContinuationResult result = inTest.continueMigrationOnEvent(ContinuationEvent.REQUIRES_FULL_VAULT_DIR_SCAN);
			System.out.println("received result " + result + " on " + Thread.currentThread().getName());
			Assertions.assertEquals(ContinuationResult.PROCEED, result);
		});

		threadPool.shutdown();
	}

}