package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

class AbstractHealthCheckTest {

	@Test
	@DisplayName("stream terminates after reading all results")
	public void testConsumeStream() {
		Path pathToVault = Mockito.mock(Path.class);
		VaultConfig config = Mockito.mock(VaultConfig.class);
		Masterkey masterkey = Mockito.mock(Masterkey.class);
		Cryptor cryptor = Mockito.mock(Cryptor.class);
		DiagnosticResult result1 = Mockito.mock(DiagnosticResult.class, "result1");
		DiagnosticResult result2 = Mockito.mock(DiagnosticResult.class, "result2");
		AbstractHealthCheck check = new AbstractHealthCheck() {
			@Override
			protected void check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, Consumer<DiagnosticResult> resultCollector) {
				resultCollector.accept(result1);
				resultCollector.accept(result2);
			}
		};

		var stream = check.check(pathToVault, config, masterkey, cryptor);

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
			CountDownLatch cdl = new CountDownLatch(2);
			stream.forEach(result -> cdl.countDown());
			cdl.await();
		});
	}

	@Test
	@DisplayName("health check waits if result is not consumed")
	public void testCheckerBlocks() throws InterruptedException {
		Path pathToVault = Mockito.mock(Path.class);
		VaultConfig config = Mockito.mock(VaultConfig.class);
		Masterkey masterkey = Mockito.mock(Masterkey.class);
		Cryptor cryptor = Mockito.mock(Cryptor.class);
		DiagnosticResult result1 = Mockito.mock(DiagnosticResult.class, "result1");
		CountDownLatch cdl1 = new CountDownLatch(1);
		CountDownLatch cdl2 = new CountDownLatch(1);
		AbstractHealthCheck check = new AbstractHealthCheck() {
			@Override
			protected void check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, Consumer<DiagnosticResult> resultCollector) {
				cdl1.countDown();
				resultCollector.accept(result1);
				cdl2.countDown();
			}
		};

		check.check(pathToVault, config, masterkey, cryptor);

		Assertions.assertTrue(cdl1.await(1, TimeUnit.SECONDS), "must reach cdl1");
		Assertions.assertFalse(cdl2.await(1, TimeUnit.SECONDS), "must not reach cdl2");
	}

	@Test
	@DisplayName("health check can be cancelled")
	public void testCancel() {
		Path pathToVault = Mockito.mock(Path.class);
		VaultConfig config = Mockito.mock(VaultConfig.class);
		Masterkey masterkey = Mockito.mock(Masterkey.class);
		Cryptor cryptor = Mockito.mock(Cryptor.class);
		DiagnosticResult result1 = Mockito.mock(DiagnosticResult.class, "result1");
		DiagnosticResult result2 = Mockito.mock(DiagnosticResult.class, "result2");
		AbstractHealthCheck check = new AbstractHealthCheck() {
			@Override
			protected void check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, Consumer<DiagnosticResult> resultCollector) {
				resultCollector.accept(result1);
				resultCollector.accept(result2);
				System.out.println("ad");
			}
		};

		var stream = check.check(pathToVault, config, masterkey, cryptor);

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
			stream.forEach(result -> {
				if (result == result1) {
					check.cancel();
				}
				Assertions.assertNotEquals(result2, result);
			});
		});
	}

}