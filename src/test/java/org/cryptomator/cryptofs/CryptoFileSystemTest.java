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
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileSystem;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.spi.FileSystemProvider;
import java.util.Set;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType;
import org.cryptomator.cryptolib.api.Cryptor;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import de.bechte.junit.runners.context.HierarchicalContextRunner;

@RunWith(HierarchicalContextRunner.class)
public class CryptoFileSystemTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private final Path pathToVault = mock(Path.class);
	private final CryptoFileSystemProperties properties = mock(CryptoFileSystemProperties.class);
	private final Cryptor cryptor = mock(Cryptor.class);
	private final CryptoFileSystemProvider provider = mock(CryptoFileSystemProvider.class);
	private final CryptoFileSystems cryptoFileSystems = mock(CryptoFileSystems.class);
	private final CryptoFileStore fileStore = mock(CryptoFileStore.class);
	private final OpenCryptoFiles openCryptoFiles = mock(OpenCryptoFiles.class);
	private final CryptoPathMapper cryptoPathMapper = mock(CryptoPathMapper.class);
	private final LongFileNameProvider longFileNameProvider = mock(LongFileNameProvider.class);
	private final CryptoFileAttributeProvider fileAttributeProvider = mock(CryptoFileAttributeProvider.class);
	private final CryptoFileAttributeViewProvider fileAttributeViewProvider = mock(CryptoFileAttributeViewProvider.class);
	private final PathMatcherFactory pathMatcherFactory = mock(PathMatcherFactory.class);
	private final CryptoPathFactory cryptoPathFactory = mock(CryptoPathFactory.class);
	private final CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);
	private final RootDirectoryInitializer rootDirectoryInitializer = mock(RootDirectoryInitializer.class);

	private final CryptoPath root = mock(CryptoPath.class);
	private final CryptoPath empty = mock(CryptoPath.class);

	private CryptoFileSystem inTest;

	@Before
	public void setup() {
		when(cryptoPathFactory.rootFor(any())).thenReturn(root);
		when(cryptoPathFactory.emptyFor(any())).thenReturn(empty);

		inTest = new CryptoFileSystem(pathToVault, properties, cryptor, provider, cryptoFileSystems, fileStore, openCryptoFiles, cryptoPathMapper, longFileNameProvider, fileAttributeProvider, fileAttributeViewProvider,
				pathMatcherFactory, cryptoPathFactory, stats, rootDirectoryInitializer);
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

	public class Delete {

		@Test
		public void testDeleteExistingFile() throws IOException {
			Path ciphertextFilePath = Mockito.mock(Path.class, "ciphertextFile");
			FileSystem physicalFs = Mockito.mock(FileSystem.class);
			FileSystemProvider physicalFsProv = Mockito.mock(FileSystemProvider.class);
			when(ciphertextFilePath.getFileSystem()).thenReturn(physicalFs);
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(true);

			CryptoPath cleartextPath = Mockito.mock(CryptoPath.class, "cleartext");
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
			inTest.delete(cleartextPath);

			verify(physicalFsProv).deleteIfExists(ciphertextFilePath);
		}

		@Test
		public void testDeleteExistingDirectory() throws IOException {
			Path ciphertextFilePath = Mockito.mock(Path.class, "ciphertextFile");
			Path ciphertextDirFilePath = Mockito.mock(Path.class, "ciphertextDirFile");
			Path ciphertextDirPath = Mockito.mock(Path.class, "ciphertextDir");
			FileSystem physicalFs = Mockito.mock(FileSystem.class);
			FileSystemProvider physicalFsProv = Mockito.mock(FileSystemProvider.class);
			when(ciphertextFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirPath.getFileSystem()).thenReturn(physicalFs);
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(false);
			CryptoPath cleartextPath = Mockito.mock(CryptoPath.class, "cleartext");
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextDirFilePath);
			when(cryptoPathMapper.getCiphertextDirPath(cleartextPath)).thenReturn(ciphertextDirPath);
			inTest.delete(cleartextPath);

			verify(physicalFsProv).delete(ciphertextDirPath);
			verify(physicalFsProv).deleteIfExists(ciphertextDirFilePath);
		}

		@Test
		public void testDeleteNonExistingFileOrDir() throws IOException {
			Path ciphertextFilePath = Mockito.mock(Path.class, "ciphertextFile");
			Path ciphertextDirFilePath = Mockito.mock(Path.class, "ciphertextDirFile");
			Path ciphertextDirPath = Mockito.mock(Path.class, "ciphertextDir");
			FileSystem physicalFs = Mockito.mock(FileSystem.class);
			FileSystemProvider physicalFsProv = Mockito.mock(FileSystemProvider.class);
			when(ciphertextFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirPath.getFileSystem()).thenReturn(physicalFs);
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(false);
			CryptoPath cleartextPath = Mockito.mock(CryptoPath.class, "cleartext");
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextDirFilePath);
			when(cryptoPathMapper.getCiphertextDirPath(cleartextPath)).thenReturn(ciphertextDirPath);

			Mockito.when(cleartextPath.toString()).thenReturn("clear/text/path");
			Mockito.doThrow(new NoSuchFileException("cleartext")).when(physicalFsProv).delete(ciphertextDirPath);
			thrown.expect(NoSuchFileException.class);
			inTest.delete(cleartextPath);
		}

		@Test
		public void testDeleteNonEmptyDir() throws IOException {
			Path ciphertextFilePath = Mockito.mock(Path.class, "ciphertextFile");
			Path ciphertextDirFilePath = Mockito.mock(Path.class, "ciphertextDirFile");
			Path ciphertextDirPath = Mockito.mock(Path.class, "ciphertextDir");
			FileSystem physicalFs = Mockito.mock(FileSystem.class);
			FileSystemProvider physicalFsProv = Mockito.mock(FileSystemProvider.class);
			when(ciphertextFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirPath.getFileSystem()).thenReturn(physicalFs);
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(false);
			CryptoPath cleartextPath = Mockito.mock(CryptoPath.class, "cleartext");
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextDirFilePath);
			when(cryptoPathMapper.getCiphertextDirPath(cleartextPath)).thenReturn(ciphertextDirPath);

			Mockito.doThrow(new DirectoryNotEmptyException("ciphertextDir")).when(physicalFsProv).delete(ciphertextDirPath);
			thrown.expect(DirectoryNotEmptyException.class);
			inTest.delete(cleartextPath);
		}

	}

}
