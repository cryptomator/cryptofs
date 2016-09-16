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
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystem;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.StandardCopyOption;
import java.nio.file.spi.FileSystemProvider;
import java.util.Iterator;
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
	private final DirectoryIdProvider dirIdProvider = mock(DirectoryIdProvider.class);
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

		inTest = new CryptoFileSystem(pathToVault, properties, cryptor, provider, cryptoFileSystems, fileStore, openCryptoFiles, cryptoPathMapper, dirIdProvider, longFileNameProvider, fileAttributeProvider,
				fileAttributeViewProvider, pathMatcherFactory, cryptoPathFactory, stats, rootDirectoryInitializer);
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

		private final CryptoPath cleartextPath = mock(CryptoPath.class, "cleartext");
		private final Path ciphertextFilePath = mock(Path.class, "ciphertextFile");
		private final Path ciphertextDirFilePath = mock(Path.class, "ciphertextDirFile");
		private final Path ciphertextDirPath = mock(Path.class, "ciphertextDir");
		private final FileSystem physicalFs = mock(FileSystem.class);
		private final FileSystemProvider physicalFsProv = mock(FileSystemProvider.class);

		@Before
		public void setup() throws IOException {
			when(ciphertextFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirPath.getFileSystem()).thenReturn(physicalFs);
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextDirFilePath);
			when(cryptoPathMapper.getCiphertextDirPath(cleartextPath)).thenReturn(ciphertextDirPath);
		}

		@Test
		public void testDeleteExistingFile() throws IOException {
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(true);

			inTest.delete(cleartextPath);
			verify(physicalFsProv).deleteIfExists(ciphertextFilePath);
		}

		@Test
		public void testDeleteExistingDirectory() throws IOException {
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(false);

			inTest.delete(cleartextPath);
			verify(physicalFsProv).delete(ciphertextDirPath);
			verify(physicalFsProv).deleteIfExists(ciphertextDirFilePath);
			verify(dirIdProvider).invalidate(ciphertextDirFilePath);
		}

		@Test
		public void testDeleteNonExistingFileOrDir() throws IOException {
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(false);
			Mockito.doThrow(new NoSuchFileException("cleartext")).when(physicalFsProv).delete(ciphertextDirPath);

			thrown.expect(NoSuchFileException.class);
			inTest.delete(cleartextPath);
		}

		@Test
		public void testDeleteNonEmptyDir() throws IOException {
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(false);
			Mockito.doThrow(new DirectoryNotEmptyException("ciphertextDir")).when(physicalFsProv).delete(ciphertextDirPath);

			thrown.expect(DirectoryNotEmptyException.class);
			inTest.delete(cleartextPath);
		}

	}

	public class Move {

		private final CryptoPath cleartextSource = mock(CryptoPath.class, "cleartextSource");
		private final CryptoPath cleartextTarget = mock(CryptoPath.class, "cleartextTarget");
		private final Path ciphertextSourceFile = mock(Path.class, "ciphertextSourceFile");
		private final Path ciphertextSourceDirFile = mock(Path.class, "ciphertextSourceDirFile");
		private final Path ciphertextTargetFile = mock(Path.class, "ciphertextTargetFile");
		private final Path ciphertextTargetDirFile = mock(Path.class, "ciphertextTargetDirFile");
		private final Path ciphertextTargetDir = mock(Path.class, "ciphertextTargetDir");
		private final FileSystem physicalFs = mock(FileSystem.class);
		private final FileSystemProvider physicalFsProv = mock(FileSystemProvider.class);

		@Before
		public void setup() throws IOException {
			when(ciphertextSourceFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextSourceDirFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextTargetFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextTargetDirFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextTargetDir.getFileSystem()).thenReturn(physicalFs);
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.FILE)).thenReturn(ciphertextSourceFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextSourceDirFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextTarget, CiphertextFileType.FILE)).thenReturn(ciphertextTargetFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextTarget, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextTargetDirFile);
			when(cryptoPathMapper.getCiphertextDir(cleartextTarget)).thenReturn(new CryptoPathMapper.Directory("42", ciphertextTargetDir));
		}

		@Test
		public void moveNonExistingFile() throws IOException {
			Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
			Mockito.doThrow(new NoSuchFileException("ciphertextSourceDirFile")).when(physicalFsProv).checkAccess(ciphertextSourceDirFile);

			thrown.expect(NoSuchFileException.class);
			inTest.move(cleartextSource, cleartextTarget);
		}

		@Test
		public void moveToAlreadyExistingFile() throws IOException {
			Mockito.doThrow(new FileAlreadyExistsException("ciphertextTargetFile")).when(physicalFsProv).move(ciphertextSourceFile, ciphertextTargetFile);

			thrown.expect(FileAlreadyExistsException.class);
			inTest.move(cleartextSource, cleartextTarget);
		}

		@Test
		public void moveFile() throws IOException {
			Mockito.doThrow(new NoSuchFileException("ciphertextSourceDirFile")).when(physicalFsProv).checkAccess(ciphertextSourceDirFile);

			CopyOption option1 = mock(CopyOption.class);
			CopyOption option2 = mock(CopyOption.class);
			inTest.move(cleartextSource, cleartextTarget, option1, option2);
			verify(physicalFsProv).move(ciphertextSourceFile, ciphertextTargetFile, option1, option2);
		}

		@Test
		public void moveDirectoryDontReplaceExisting() throws IOException {
			Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);

			CopyOption option1 = mock(CopyOption.class);
			CopyOption option2 = mock(CopyOption.class);
			inTest.move(cleartextSource, cleartextTarget, option1, option2);
			verify(physicalFsProv).move(ciphertextSourceDirFile, ciphertextTargetDirFile, option1, option2);
			verify(dirIdProvider).invalidate(ciphertextSourceDirFile);
		}

		@Test
		@SuppressWarnings("unchecked")
		public void moveDirectoryReplaceExisting() throws IOException {
			Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
			DirectoryStream<Path> ds = mock(DirectoryStream.class);
			Iterator<Path> iter = mock(Iterator.class);
			when(physicalFsProv.newDirectoryStream(Mockito.same(ciphertextTargetDir), Mockito.any())).thenReturn(ds);
			when(ds.iterator()).thenReturn(iter);
			when(iter.hasNext()).thenReturn(false);

			inTest.move(cleartextSource, cleartextTarget, StandardCopyOption.REPLACE_EXISTING);
			verify(physicalFsProv).delete(ciphertextTargetDir);
			verify(physicalFsProv).move(ciphertextSourceDirFile, ciphertextTargetDirFile, StandardCopyOption.REPLACE_EXISTING);
			verify(dirIdProvider).invalidate(ciphertextSourceDirFile);
			verify(dirIdProvider).invalidate(ciphertextTargetDirFile);
		}

		@Test
		@SuppressWarnings("unchecked")
		public void moveDirectoryReplaceExistingNonEmpty() throws IOException {
			Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
			DirectoryStream<Path> ds = mock(DirectoryStream.class);
			Iterator<Path> iter = mock(Iterator.class);
			when(physicalFsProv.newDirectoryStream(Mockito.same(ciphertextTargetDir), Mockito.any())).thenReturn(ds);
			when(ds.iterator()).thenReturn(iter);
			when(iter.hasNext()).thenReturn(true);

			try {
				thrown.expect(DirectoryNotEmptyException.class);
				inTest.move(cleartextSource, cleartextTarget, StandardCopyOption.REPLACE_EXISTING);
			} finally {
				verify(physicalFsProv, Mockito.never()).move(Mockito.any(), Mockito.any(), Mockito.anyVararg());
			}
		}

		@Test
		public void moveDirectoryReplaceExistingAtomically() throws IOException {
			Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);

			try {
				thrown.expect(AtomicMoveNotSupportedException.class);
				inTest.move(cleartextSource, cleartextTarget, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
			} finally {
				verify(physicalFsProv, Mockito.never()).move(Mockito.any(), Mockito.any(), Mockito.anyVararg());
			}
		}

	}

}
