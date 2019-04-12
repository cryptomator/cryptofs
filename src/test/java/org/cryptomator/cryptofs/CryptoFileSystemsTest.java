package org.cryptomator.cryptofs;

import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Path;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CryptoFileSystemsTest {

	private final Path path = mock(Path.class);
	private final Path normalizedPath = mock(Path.class);
	private final CryptoFileSystemProvider provider = mock(CryptoFileSystemProvider.class);
	private final CryptoFileSystemProperties properties = mock(CryptoFileSystemProperties.class);
	private final CryptoFileSystemComponent cryptoFileSystemComponent = mock(CryptoFileSystemComponent.class);
	private final CryptoFileSystemImpl cryptoFileSystem = mock(CryptoFileSystemImpl.class);

	private final CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent = mock(CryptoFileSystemProviderComponent.class);
	private final CryptoFileSystemComponent.Builder cryptoFileSystemComponentBuilder = mock(CryptoFileSystemComponent.Builder.class);

	private final CryptoFileSystems inTest = new CryptoFileSystems(cryptoFileSystemProviderComponent);

	@BeforeEach
	public void setup() {
		when(cryptoFileSystemProviderComponent.newCryptoFileSystemComponent()).thenReturn(cryptoFileSystemComponentBuilder);
		when(cryptoFileSystemComponentBuilder.provider(any())).thenReturn(cryptoFileSystemComponentBuilder);
		when(cryptoFileSystemComponentBuilder.pathToVault(any())).thenReturn(cryptoFileSystemComponentBuilder);
		when(cryptoFileSystemComponentBuilder.properties(any())).thenReturn(cryptoFileSystemComponentBuilder);
		when(cryptoFileSystemComponentBuilder.build()).thenReturn(cryptoFileSystemComponent);
		when(cryptoFileSystemComponent.cryptoFileSystem()).thenReturn(cryptoFileSystem);
		when(path.normalize()).thenReturn(normalizedPath);
	}

	@Test
	public void testContainsReturnsFalseForNonContainedFileSystem() {
		Assertions.assertFalse(inTest.contains(cryptoFileSystem));
	}

	@Test
	public void testContainsReturnsTrueForContainedFileSystem() throws IOException {
		CryptoFileSystemImpl impl = inTest.create(provider, path, properties);

		Assertions.assertSame(cryptoFileSystem, impl);
		Assertions.assertTrue(inTest.contains(cryptoFileSystem));
		verify(cryptoFileSystemComponentBuilder).provider(provider);
		verify(cryptoFileSystemComponentBuilder).properties(properties);
		verify(cryptoFileSystemComponentBuilder).pathToVault(normalizedPath);
		verify(cryptoFileSystemComponentBuilder).build();
	}

	@Test
	public void testCreateThrowsFileSystemAlreadyExistsExceptionIfInvokedWithSamePathTwice() throws IOException {
		inTest.create(provider, path, properties);

		Assertions.assertThrows(FileSystemAlreadyExistsException.class, () -> {
			inTest.create(provider, path, properties);
		});
	}

	@Test
	public void testCreateDoesNotThrowFileSystemAlreadyExistsExceptionIfFileSystemIsRemovedBefore() throws IOException {
		CryptoFileSystemImpl fileSystem = inTest.create(provider, path, properties);
		inTest.remove(fileSystem);

		inTest.create(provider, path, properties);
	}

	@Test
	public void testGetReturnsFileSystemForPathIfItExists() throws IOException {
		inTest.create(provider, path, properties);

		Assertions.assertSame(cryptoFileSystem, inTest.get(path));
	}

	@Test
	public void testThrowsFileSystemNotFoundExceptionIfItDoesNotExists() {
		FileSystemNotFoundException e = Assertions.assertThrows(FileSystemNotFoundException.class, () -> {
			inTest.get(path);
		});
		MatcherAssert.assertThat(e.getMessage(), containsString(path.toString()));
	}

}
