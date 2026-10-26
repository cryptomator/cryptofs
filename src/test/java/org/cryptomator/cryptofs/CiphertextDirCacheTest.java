package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

public class CiphertextDirCacheTest {

	CiphertextDirCache cache;
	CryptoPath clearPath;
	CiphertextDirCache.CipherDirLoader dirLoader;


	@BeforeEach
	public void beforeEach() throws IOException {
		cache = new CiphertextDirCache();
		clearPath = Mockito.mock(CryptoPath.class);
		dirLoader = Mockito.mock(CiphertextDirCache.CipherDirLoader.class);
		var cipherDir = Mockito.mock(CiphertextDirectory.class);
		Mockito.when(dirLoader.load()).thenReturn(cipherDir);
	}

	@Test
	public void testPuttingNewEntryTriggersLoader() throws IOException {
		var cipherDir = Mockito.mock(CiphertextDirectory.class);
		Mockito.when(dirLoader.load()).thenReturn(cipherDir);

		var result = cache.get(clearPath, dirLoader);
		Assertions.assertEquals(cipherDir, result);
		Mockito.verify(dirLoader).load();
	}

	@Test
	public void testPuttingKnownEntryDoesNotTriggerLoader() throws IOException {
		Mockito.when(dirLoader.load()).thenReturn(Mockito.mock(CiphertextDirectory.class));
		var dirLoader2 = Mockito.mock(CiphertextDirCache.CipherDirLoader.class);

		var result = cache.get(clearPath, dirLoader);
		var result2 = cache.get(clearPath, dirLoader2);
		Assertions.assertEquals(result2, result);
		Mockito.verify(dirLoader2, Mockito.never()).load();
	}

	@Test
	public void testFailingLoaderLeavesNoEntry() throws IOException {
		var failingLoader = Mockito.mock(CiphertextDirCache.CipherDirLoader.class);
		var expected = new IOException("broken dir file");
		Mockito.doThrow(expected).when(failingLoader).load();

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
			var actual = Assertions.assertThrows(IOException.class, () -> cache.get(clearPath, failingLoader));
			Assertions.assertSame(expected, actual);
			cache.get(clearPath, dirLoader); //triggers loader instead of waiting for the failed one
		});
		Mockito.verify(dirLoader).load();
	}

	@Test
	public void testConcurrentCallerReceivesLoaderException() throws Exception {
		var loaderEntered = new CountDownLatch(1);
		var loaderMayFail = new CountDownLatch(1);
		var expected = new IOException("broken dir file");
		var failingLoader = Mockito.mock(CiphertextDirCache.CipherDirLoader.class);
		Mockito.doAnswer(_ -> {
			loaderEntered.countDown();
			loaderMayFail.await();
			throw expected;
		}).when(failingLoader).load();
		var waiterThread = new AtomicReference<Thread>();

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
			try (var executor = Executors.newFixedThreadPool(2)) {
				var loading = executor.submit(() -> cache.get(clearPath, failingLoader));
				loaderEntered.await();
				var waiting = executor.submit(() -> {
					waiterThread.set(Thread.currentThread());
					return cache.get(clearPath, dirLoader);
				});
				while (waiterThread.get() == null || waiterThread.get().getState() != Thread.State.WAITING) {
					Thread.onSpinWait();
				}
				loaderMayFail.countDown();

				var loadingException = Assertions.assertThrows(ExecutionException.class, loading::get);
				var waitingException = Assertions.assertThrows(ExecutionException.class, waiting::get);
				Assertions.assertSame(expected, loadingException.getCause());
				Assertions.assertSame(expected, waitingException.getCause());
			}
		});
		Mockito.verify(dirLoader, Mockito.never()).load();
	}

	@Nested
	public class RemovalTest {

		CryptoPath prefixPath = Mockito.mock(CryptoPath.class);

		@Test
		public void entryRemovedOnPrefixSuccess() throws IOException {
			Mockito.when(clearPath.startsWith(prefixPath)).thenReturn(true);

			cache.get(clearPath, dirLoader); //triggers loader
			cache.removeAllKeysWithPrefix(prefixPath);
			cache.get(clearPath, dirLoader); //triggers loader

			Mockito.verify(dirLoader, Mockito.times(2)).load();
		}

		@Test
		public void entryStaysOnPrefixFailure() throws IOException {
			Mockito.when(clearPath.startsWith(prefixPath)).thenReturn(false);

			cache.get(clearPath, dirLoader); //triggers loader
			cache.removeAllKeysWithPrefix(prefixPath);
			cache.get(clearPath, dirLoader); //does not trigger

			Mockito.verify(dirLoader).load();
		}
	}


	@Nested
	public class RemapTest {

		CryptoPath newClearPath;
		CryptoPath oldPrefixPath;
		CryptoPath newPrefixPath;

		@BeforeEach
		public void beforeEach() throws IOException {
			newClearPath = Mockito.mock(CryptoPath.class);
			oldPrefixPath = Mockito.mock(CryptoPath.class);
			newPrefixPath = Mockito.mock(CryptoPath.class);
			Mockito.when(oldPrefixPath.relativize(Mockito.any(Path.class))).thenReturn(oldPrefixPath);
			Mockito.when(newPrefixPath.resolve(Mockito.any(Path.class))).thenReturn(newClearPath);
		}

		@Test
		public void entryRemappedOnPrefixSuccess() throws IOException {
			Mockito.when(clearPath.startsWith(oldPrefixPath)).thenReturn(true);

			cache.get(clearPath, dirLoader); //triggers loader
			cache.recomputeAllKeysWithPrefix(oldPrefixPath, newPrefixPath);
			cache.get(clearPath, dirLoader); //does trigger
			cache.get(newClearPath, dirLoader); //does not trigger

			Mockito.verify(dirLoader, Mockito.times(2)).load();
		}

		@Test
		public void entryUntouchedOnPrefixFailure() throws IOException {
			Mockito.when(clearPath.startsWith(oldPrefixPath)).thenReturn(false);

			cache.get(clearPath, dirLoader); //triggers loader
			cache.recomputeAllKeysWithPrefix(oldPrefixPath, newPrefixPath);
			cache.get(clearPath, dirLoader); //does not trigger
			cache.get(newClearPath, dirLoader); //does trigger

			Mockito.verify(dirLoader, Mockito.times(2)).load();
		}
	}

}