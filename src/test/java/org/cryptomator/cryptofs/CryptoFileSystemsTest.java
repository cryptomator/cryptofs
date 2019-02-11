package org.cryptomator.cryptofs;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.io.IOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Path;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CryptoFileSystemsTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private final Path path = mock(Path.class);
	private final Path normalizedPath = mock(Path.class);
	private final CryptoFileSystemProvider provider = mock(CryptoFileSystemProvider.class);
	private final CryptoFileSystemProperties properties = mock(CryptoFileSystemProperties.class);
	private final CryptoFileSystemComponent cryptoFileSystemComponent = mock(CryptoFileSystemComponent.class);
	private final CryptoFileSystemImpl cryptoFileSystem = mock(CryptoFileSystemImpl.class);

	private final CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent = mock(CryptoFileSystemProviderComponent.class);
	private final CryptoFileSystemComponent.Builder cryptoFileSystemComponentBuilder = mock(CryptoFileSystemComponent.Builder.class);

	private final CryptoFileSystems inTest = new CryptoFileSystems(cryptoFileSystemProviderComponent);

	@Before
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
		assertThat(inTest.contains(cryptoFileSystem), is(false));
	}

	@Test
	public void testContainsReturnsTrueForContainedFileSystem() throws IOException {
		CryptoFileSystemImpl impl = inTest.create(provider, path, properties);

		assertThat(impl, is(cryptoFileSystem));
		assertThat(inTest.contains(cryptoFileSystem), is(true));
		verify(cryptoFileSystemComponentBuilder).provider(provider);
		verify(cryptoFileSystemComponentBuilder).properties(properties);
		verify(cryptoFileSystemComponentBuilder).pathToVault(normalizedPath);
		verify(cryptoFileSystemComponentBuilder).build();
	}

	@Test
	public void testCreateThrowsFileSystemAlreadyExistsExceptionIfInvokedWithSamePathTwice() throws IOException {
		inTest.create(provider, path, properties);

		thrown.expect(FileSystemAlreadyExistsException.class);

		inTest.create(provider, path, properties);
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

		assertThat(inTest.get(path), is(cryptoFileSystem));
	}

	@Test
	public void testThrowsFileSystemNotFoundExceptionIfItDoesNotExists() throws IOException {
		thrown.expect(FileSystemNotFoundException.class);
		thrown.expectMessage(path.toString());

		inTest.get(path);
	}

}
