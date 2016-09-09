package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.Set;

import org.cryptomator.cryptolib.api.Cryptor;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class CryptoFileSystemTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private Path pathToVault = mock(Path.class);
	private CryptoFileSystemProperties properties = mock(CryptoFileSystemProperties.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private CryptoFileSystemProvider provider = mock(CryptoFileSystemProvider.class);
	private CryptoFileSystems cryptoFileSystems = mock(CryptoFileSystems.class);
	private CryptoFileStore fileStore = mock(CryptoFileStore.class);
	private OpenCryptoFiles openCryptoFiles = mock(OpenCryptoFiles.class);
	private CryptoPathMapper cryptoPathMapper = mock(CryptoPathMapper.class);
	private LongFileNameProvider longFileNameProvider = mock(LongFileNameProvider.class);
	private CryptoFileAttributeProvider fileAttributeProvider = mock(CryptoFileAttributeProvider.class);
	private CryptoFileAttributeViewProvider fileAttributeViewProvider = mock(CryptoFileAttributeViewProvider.class);
	private PathMatcherFactory pathMatcherFactory = mock(PathMatcherFactory.class);
	private CryptoPathFactory cryptoPathFactory = mock(CryptoPathFactory.class);
	private RootDirectoryInitializer rootDirectoryInitializer = mock(RootDirectoryInitializer.class);

	private CryptoPath root = mock(CryptoPath.class);
	private CryptoPath empty = mock(CryptoPath.class);

	private CryptoFileSystem inTest;

	@Before
	public void setup() {
		when(cryptoPathFactory.rootFor(any())).thenReturn(root);
		when(cryptoPathFactory.emptyFor(any())).thenReturn(empty);

		inTest = new CryptoFileSystem(pathToVault, properties, cryptor, provider, cryptoFileSystems, fileStore, openCryptoFiles, cryptoPathMapper, longFileNameProvider, fileAttributeProvider, fileAttributeViewProvider,
				pathMatcherFactory, cryptoPathFactory, rootDirectoryInitializer);
	}

	@Test
	public void testProviderReturnsProvider() {
		assertThat(inTest.provider(), is(provider));
	}

	@Test // TODO markuskreusch: should not return false but look into delegate filestore and flags
	public void testIsReadOnlyReturnsFalse() {
		assertFalse(inTest.isReadOnly());
	}

	@Test
	public void testGetSeparatorReturnsSlash() {
		assertThat(inTest.getSeparator(), is("/"));
	}

	@Test
	public void testGetRootDirectoriesReturnsRoot() {
		assertThat(inTest.getRootDirectories(), containsInAnyOrder(root));
	}

	@Test
	public void testGetFileStoresReturnsFileStore() {
		assertThat(inTest.getFileStore(), is(fileStore));
	}

	@Test
	public void testCloseRemovesThisFromCryptoFileSystems() {
		inTest.close();

		verify(cryptoFileSystems).remove(inTest);
	}

	@Test
	public void testCloseDestroysCryptor() {
		inTest.close();

		verify(cryptor).destroy();
	}

	@Test
	public void testIsOpenReturnsTrueWhenContainedInCryptoFileSystems() {
		when(cryptoFileSystems.contains(inTest)).thenReturn(true);

		assertTrue(inTest.isOpen());
	}

	@Test
	public void testIsOpenReturnsFalseWhenNotContainedInCryptoFileSystems() {
		when(cryptoFileSystems.contains(inTest)).thenReturn(false);

		assertFalse(inTest.isOpen());
	}

	@Test // TODO markuskreusch: is this behaviour correct?
	public void testSupportedFileAttributeViewsDelegatesToFileSystemOfVaultLocation() {
		@SuppressWarnings("unchecked")
		Set<String> expected = mock(Set.class);
		FileSystem fileSystemOfVaultLocation = mock(FileSystem.class);
		when(pathToVault.getFileSystem()).thenReturn(fileSystemOfVaultLocation);
		when(fileSystemOfVaultLocation.supportedFileAttributeViews()).thenReturn(expected);

		assertThat(inTest.supportedFileAttributeViews(), is(sameInstance(expected)));
	}

	@Test
	public void testGetPathDelegatesToCryptoPathFactory() {
		CryptoPath expected = mock(CryptoPath.class);
		String first = "abc";
		String[] more = {"cde", "efg"};
		when(cryptoPathFactory.getPath(inTest, first, more)).thenReturn(expected);

		assertThat(inTest.getPath(first, more), is(sameInstance(expected)));
	}

	@Test
	public void testGetPathMatcherDelegatesToPathMatcherFactory() {
		PathMatcher expected = mock(PathMatcher.class);
		String syntaxAndPattern = "asd";
		when(pathMatcherFactory.pathMatcherFrom(syntaxAndPattern)).thenReturn(expected);

		assertThat(inTest.getPathMatcher(syntaxAndPattern), is(expected));
	}

	@Test
	public void testGetUserPrincipalLookupServiceThrowsUnsupportedOperationException() {
		thrown.expect(UnsupportedOperationException.class);

		inTest.getUserPrincipalLookupService();
	}

	@Test
	public void testNewWatchServiceThrowsUnsupportedOperationException() throws IOException {
		thrown.expect(UnsupportedOperationException.class);

		inTest.newWatchService();
	}

}
