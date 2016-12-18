package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.CryptoFileSystemModuleMatcher.withPathToVault;
import static org.cryptomator.cryptofs.CryptoFileSystemModuleMatcher.withProperties;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Path;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class CryptoFileSystemsTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private Path path = mock(Path.class);
	private Path normalizedPath = mock(Path.class);
	private CryptoFileSystemProperties properties = mock(CryptoFileSystemProperties.class);
	private CryptoFileSystemComponent cryptoFileSystemComponent = mock(CryptoFileSystemComponent.class);
	private CryptoFileSystemImpl cryptoFileSystem = mock(CryptoFileSystemImpl.class);

	private CryptoFileSystemProviderComponent cryptoFileSystemProviderComponent = mock(CryptoFileSystemProviderComponent.class);

	private CryptoFileSystems inTest = new CryptoFileSystems(cryptoFileSystemProviderComponent);

	@Before
	public void setup() {
		when(cryptoFileSystemProviderComponent.newCryptoFileSystemComponent(any())).thenReturn(cryptoFileSystemComponent);
		when(cryptoFileSystemComponent.cryptoFileSystem()).thenReturn(cryptoFileSystem);
		when(path.normalize()).thenReturn(normalizedPath);
	}

	@Test
	public void testContainsReturnsFalseForNonContainedFileSystem() {
		assertThat(inTest.contains(cryptoFileSystem), is(false));
	}

	@Test
	public void testContainsReturnsTrueForContainedFileSystem() throws IOException {
		CryptoFileSystemImpl impl = inTest.create(path, properties);

		assertThat(impl, is(cryptoFileSystem));
		assertThat(inTest.contains(cryptoFileSystem), is(true));
		verify(cryptoFileSystemProviderComponent).newCryptoFileSystemComponent(argThat(allOf( //
				withPathToVault(normalizedPath), //
				withProperties(properties))));
	}

	@Test
	public void testCreateThrowsFileSystemAlreadyExistsExceptionIfInvokedWithSamePathTwice() throws IOException {
		inTest.create(path, properties);

		thrown.expect(FileSystemAlreadyExistsException.class);

		inTest.create(path, properties);
	}

	@Test
	public void testCreateDoesNotThrowFileSystemAlreadyExistsExceptionIfFileSystemIsRemovedBefore() throws IOException {
		CryptoFileSystemImpl fileSystem = inTest.create(path, properties);
		inTest.remove(fileSystem);

		inTest.create(path, properties);
	}

	@Test
	public void testGetReturnsFileSystemForPathIfItExists() throws IOException {
		inTest.create(path, properties);

		assertThat(inTest.get(path), is(cryptoFileSystem));
	}

	@Test
	public void testThrowsFileSystemNotFoundExceptionIfItDoesNotExists() throws IOException {
		thrown.expect(FileSystemNotFoundException.class);
		thrown.expectMessage(path.toString());

		inTest.get(path);
	}

}
