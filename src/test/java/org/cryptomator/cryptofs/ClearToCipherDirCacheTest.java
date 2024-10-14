package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Path;

public class ClearToCipherDirCacheTest {

	ClearToCipherDirCache cache;
	CryptoPath clearPath;
	ClearToCipherDirCache.CipherDirLoader dirLoader;


	@BeforeEach
	public void beforeEach() throws IOException {
		cache = new ClearToCipherDirCache();
		clearPath = Mockito.mock(CryptoPath.class);
		dirLoader = Mockito.mock(ClearToCipherDirCache.CipherDirLoader.class);
		var cipherDir = Mockito.mock(CipherDir.class);
		Mockito.when(dirLoader.load()).thenReturn(cipherDir);
	}

	@Test
	public void testPuttingNewEntryTriggersLoader() throws IOException {
		var cipherDir = Mockito.mock(CipherDir.class);
		Mockito.when(dirLoader.load()).thenReturn(cipherDir);

		var result = cache.putIfAbsent(clearPath, dirLoader);
		Assertions.assertEquals(cipherDir, result);
		Mockito.verify(dirLoader).load();
	}

	@Test
	public void testPuttingKnownEntryDoesNotTriggerLoader() throws IOException {
		Mockito.when(dirLoader.load()).thenReturn(Mockito.mock(CipherDir.class));
		var dirLoader2 = Mockito.mock(ClearToCipherDirCache.CipherDirLoader.class);

		var result = cache.putIfAbsent(clearPath, dirLoader);
		var result2 = cache.putIfAbsent(clearPath, dirLoader2);
		Assertions.assertEquals(result2, result);
		Mockito.verify(dirLoader2, Mockito.never()).load();
	}

	@Nested
	public class RemovalTest {

		CryptoPath prefixPath = Mockito.mock(CryptoPath.class);

		@Test
		public void entryRemovedOnPrefixSuccess() throws IOException {
			Mockito.when(clearPath.startsWith(prefixPath)).thenReturn(true);

			cache.putIfAbsent(clearPath, dirLoader); //triggers loader
			cache.removeAllKeysWithPrefix(prefixPath);
			cache.putIfAbsent(clearPath, dirLoader); //triggers loader

			Mockito.verify(dirLoader, Mockito.times(2)).load();
		}

		@Test
		public void entryStaysOnPrefixFailure() throws IOException {
			Mockito.when(clearPath.startsWith(prefixPath)).thenReturn(false);

			cache.putIfAbsent(clearPath, dirLoader); //triggers loader
			cache.removeAllKeysWithPrefix(prefixPath);
			cache.putIfAbsent(clearPath, dirLoader); //does not trigger

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
			Mockito.when(oldPrefixPath.relativize(Mockito.any())).thenReturn(oldPrefixPath);
			Mockito.when(newPrefixPath.resolve((Path) Mockito.any())).thenReturn(newClearPath);
		}

		@Test
		public void entryRemappedOnPrefixSuccess() throws IOException {
			Mockito.when(clearPath.startsWith(oldPrefixPath)).thenReturn(true);

			cache.putIfAbsent(clearPath, dirLoader); //triggers loader
			cache.recomputeAllKeysWithPrefix(oldPrefixPath, newPrefixPath);
			cache.putIfAbsent(clearPath, dirLoader); //does trigger
			cache.putIfAbsent(newClearPath, dirLoader); //does not trigger

			Mockito.verify(dirLoader, Mockito.times(2)).load();
		}

		@Test
		public void entryUntouchedOnPrefixFailure() throws IOException {
			Mockito.when(clearPath.startsWith(oldPrefixPath)).thenReturn(false);

			cache.putIfAbsent(clearPath, dirLoader); //triggers loader
			cache.recomputeAllKeysWithPrefix(oldPrefixPath, newPrefixPath);
			cache.putIfAbsent(clearPath, dirLoader); //does not trigger
			cache.putIfAbsent(newClearPath, dirLoader); //does trigger

			Mockito.verify(dirLoader, Mockito.times(2)).load();
		}
	}

}