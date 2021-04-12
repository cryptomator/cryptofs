package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

class HealthCheckTest {

	private Path pathToVault = Mockito.mock(Path.class);
	private VaultConfig config = Mockito.mock(VaultConfig.class);
	private Masterkey masterkey = Mockito.mock(Masterkey.class);
	private Cryptor cryptor = Mockito.mock(Cryptor.class);
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
	@DisplayName("stream terminates after reading all results")
	public void testConsumeStream() {
		DiagnosticResult result1 = Mockito.mock(DiagnosticResult.class, "result1");
		DiagnosticResult result2 = Mockito.mock(DiagnosticResult.class, "result2");
		HealthCheck check = (pathToVault, config, masterkey, cryptor, resultCollector) -> {
			resultCollector.accept(result1);
			resultCollector.accept(result2);
		};

		var stream = check.check(pathToVault, config, masterkey, cryptor, executor);

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
			Assertions.assertEquals(2, stream.count());
		});
	}

	@Test
	@DisplayName("health check waits if result is not consumed")
	public void testCheckerBlocks() throws InterruptedException {
		DiagnosticResult result1 = Mockito.mock(DiagnosticResult.class, "result1");
		CountDownLatch cdl1 = new CountDownLatch(1);
		CountDownLatch cdl2 = new CountDownLatch(1);
		HealthCheck check = (pathToVault, config, masterkey, cryptor, resultCollector) -> {
			cdl1.countDown();
			resultCollector.accept(result1);
			cdl2.countDown();
		};

		check.check(pathToVault, config, masterkey, cryptor, executor);

		Assertions.assertTrue(cdl1.await(1, TimeUnit.SECONDS), "must reach cdl1");
		Assertions.assertFalse(cdl2.await(1, TimeUnit.SECONDS), "must not reach cdl2");
	}

	@RepeatedTest(100)
	@DisplayName("closing stream cancels health check")
	public void testClose() {
		DiagnosticResult result1 = Mockito.mock(DiagnosticResult.class, "result1");
		DiagnosticResult result2 = Mockito.mock(DiagnosticResult.class, "result2");
		CountDownLatch cdl1 = new CountDownLatch(1);
		CountDownLatch cdl2 = new CountDownLatch(1);
		CountDownLatch cdl3 = new CountDownLatch(1);
		HealthCheck check = (pathToVault, config, masterkey, cryptor, resultCollector) -> {
			try {
				cdl1.countDown(); // job started
				resultCollector.accept(result1);
				resultCollector.accept(result2);
				cdl2.countDown(); // job not finished
			} finally {
				cdl3.countDown(); // control
			}
		};


		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
			try (var stream = check.check(pathToVault, config, masterkey, cryptor, executor)) {
				cdl1.await();
			}
			cdl3.await();
			Assertions.assertEquals(1, cdl2.getCount());
		});
	}

}