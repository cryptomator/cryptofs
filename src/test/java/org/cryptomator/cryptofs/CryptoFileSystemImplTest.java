package org.cryptomator.cryptofs;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.atLeast;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.spi.AbstractInterruptibleChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystem;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.spi.FileSystemProvider;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType;
import org.cryptomator.cryptofs.CryptoPathMapper.Directory;
import org.cryptomator.cryptofs.mocks.FileChannelMock;
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
public class CryptoFileSystemImplTest {

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
	private final CryptoFileAttributeProvider fileAttributeProvider = mock(CryptoFileAttributeProvider.class);
	private final CryptoFileAttributeByNameProvider fileAttributeByNameProvider = mock(CryptoFileAttributeByNameProvider.class);
	private final CryptoFileAttributeViewProvider fileAttributeViewProvider = mock(CryptoFileAttributeViewProvider.class);
	private final PathMatcherFactory pathMatcherFactory = mock(PathMatcherFactory.class);
	private final CryptoPathFactory cryptoPathFactory = mock(CryptoPathFactory.class);
	private final CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);
	private final RootDirectoryInitializer rootDirectoryInitializer = mock(RootDirectoryInitializer.class);
	private final DirectoryStreamFactory directoryStreamFactory = mock(DirectoryStreamFactory.class);
	private final FinallyUtil finallyUtil = mock(FinallyUtil.class);
	private final ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);

	private final CryptoPath root = mock(CryptoPath.class);
	private final CryptoPath empty = mock(CryptoPath.class);

	private CryptoFileSystemImpl inTest;

	@Before
	public void setup() {
		when(cryptoPathFactory.rootFor(any())).thenReturn(root);
		when(cryptoPathFactory.emptyFor(any())).thenReturn(empty);

		inTest = new CryptoFileSystemImpl(pathToVault, properties, cryptor, provider, cryptoFileSystems, fileStore, openCryptoFiles, cryptoPathMapper, dirIdProvider, fileAttributeProvider, fileAttributeViewProvider,
				pathMatcherFactory, cryptoPathFactory, stats, rootDirectoryInitializer, fileAttributeByNameProvider, directoryStreamFactory, finallyUtil, readonlyFlag);
	}

	@Test
	public void testProviderReturnsProvider() {
		assertThat(inTest.provider(), is(provider));
	}

	@Test
	public void testEmptyPathReturnsEmptyPath() {
		assertThat(inTest.getEmptyPath(), is(empty));
	}

	@Test
	public void testGetStatsReturnsStats() {
		assertThat(inTest.getStats(), is(stats));
	}

	@Test
	public void testToStringWithOpenFileSystem() {
		assertThat(inTest.toString(), is("CryptoFileSystem(" + pathToVault.toString() + ")"));
	}

	@Test
	public void testToStringWithClosedFileSystem() throws IOException {
		inTest.close();

		assertThat(inTest.toString(), is("closed CryptoFileSystem(" + pathToVault.toString() + ")"));
	}

	@Test
	public void testGetFilestoresReturnsIterableContainingFileStore() {
		assertThat(inTest.getFileStores(), contains(fileStore));
	}

	@Test
	public void testIsReadOnlyReturnsTrueIfReadonlyFlagIsSet() {
		when(readonlyFlag.isSet()).thenReturn(true);

		assertTrue(inTest.isReadOnly());
	}

	@Test
	public void testIsReadOnlyReturnsFalseIfReadonlyFlagIsNotSet() {
		when(readonlyFlag.isSet()).thenReturn(false);

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

	public class CloseAndIsOpen {

		@SuppressWarnings("unchecked")
		@Before
		public void setup() {
			doAnswer(invocation -> {
				for (Object runnable : invocation.getArguments()) {
					((RunnableThrowingException<?>) runnable).run();
				}
				return null;
			}).when(finallyUtil).guaranteeInvocationOf(any(RunnableThrowingException.class), any(RunnableThrowingException.class), any(RunnableThrowingException.class), any(RunnableThrowingException.class));
		}

		@Test
		public void testCloseRemovesThisFromCryptoFileSystems() throws IOException {
			inTest.close();

			verify(cryptoFileSystems).remove(inTest);
		}

		@Test
		public void testCloseDestroysCryptor() throws IOException {
			inTest.close();

			verify(cryptor).destroy();
		}

		@Test
		public void testCloseClosesDirectoryStreams() throws IOException {
			inTest.close();

			verify(directoryStreamFactory).close();
		}

		@Test
		public void testCloseClosesOpenCryptoFiles() throws IOException {
			inTest.close();

			verify(openCryptoFiles).close();
		}

		@Test
		public void testIsOpenReturnsTrueWhenNotClosed() {
			assertTrue(inTest.isOpen());
		}

		@Test
		public void testIsOpenReturnsFalseWhenClosed() throws IOException {
			inTest.close();

			assertFalse(inTest.isOpen());
		}

		@Test
		public void testAssertOpenThrowsClosedFileSystemExceptionWhenClosed() throws IOException {
			inTest.close();

			thrown.expect(ClosedFileSystemException.class);

			inTest.assertOpen();
		}

	}

	public class DuplicateCloseAndIsOpen {

		@SuppressWarnings("unchecked")
		@Before
		public void setup() {
			doAnswer(invocation -> {
				for (Object runnable : invocation.getArguments()) {
					((RunnableThrowingException<?>) runnable).run();
				}
				return null;
			}).when(finallyUtil).guaranteeInvocationOf(any(RunnableThrowingException.class), any(RunnableThrowingException.class), any(RunnableThrowingException.class), any(RunnableThrowingException.class));
		}

		@Test
		public void testDuplicateCloseRemovesThisFromCryptoFileSystems() throws IOException {
			inTest.close();
			inTest.close();

			verify(cryptoFileSystems).remove(inTest);
		}

		@Test
		public void testDuplicateCloseDestroysCryptor() throws IOException {
			inTest.close();
			inTest.close();

			verify(cryptor).destroy();
		}

		@Test
		public void testDuplicateCloseClosesDirectoryStreams() throws IOException {
			inTest.close();
			inTest.close();

			verify(directoryStreamFactory).close();
		}

		@Test
		public void testDuplicateCloseClosesOpenCryptoFiles() throws IOException {
			inTest.close();
			inTest.close();

			verify(openCryptoFiles).close();
		}

		@Test
		public void testIsOpenReturnsFalseWhenClosedTwoTimes() throws IOException {
			inTest.close();
			inTest.close();

			assertFalse(inTest.isOpen());
		}

	}

	@Test // TODO markuskreusch: is this behaviour correct?
	public void testSupportedFileAttributeViewsDelegatesToFileSystemOfVaultLocation() {
		@SuppressWarnings("unchecked")
		Set<String> expected = mock(Set.class);
		when(fileStore.supportedFileAttributeViewNames()).thenReturn(expected);

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

			verify(readonlyFlag).assertWritable();
			verify(physicalFsProv).deleteIfExists(ciphertextFilePath);
		}

		@Test
		public void testDeleteExistingDirectory() throws IOException {
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(false);

			inTest.delete(cleartextPath);

			verify(readonlyFlag).assertWritable();
			verify(physicalFsProv).delete(ciphertextDirPath);
			verify(physicalFsProv).deleteIfExists(ciphertextDirFilePath);
			verify(dirIdProvider).delete(ciphertextDirFilePath);
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

	public class CopyAndMove {

		private final CryptoPath cleartextSource = mock(CryptoPath.class, "cleartextSource");
		private final CryptoPath cleartextTarget = mock(CryptoPath.class, "cleartextTarget");
		private final Path ciphertextSourceFile = mock(Path.class, "ciphertextSourceFile");
		private final Path ciphertextSourceDirFile = mock(Path.class, "ciphertextSourceDirFile");
		private final Path ciphertextSourceDir = mock(Path.class, "ciphertextSourceDir");
		private final Path ciphertextTargetFile = mock(Path.class, "ciphertextTargetFile");
		private final Path ciphertextTargetDirFile = mock(Path.class, "ciphertextTargetDirFile");
		private final Path ciphertextTargetDir = mock(Path.class, "ciphertextTargetDir");
		private final FileSystem physicalFs = mock(FileSystem.class);
		private final FileSystemProvider physicalFsProv = mock(FileSystemProvider.class);

		@Before
		public void setup() throws IOException {
			when(ciphertextSourceFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextSourceDirFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextSourceDir.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextTargetFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextTargetDirFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextTargetDir.getFileSystem()).thenReturn(physicalFs);
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.FILE)).thenReturn(ciphertextSourceFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextSourceDirFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextTarget, CiphertextFileType.FILE)).thenReturn(ciphertextTargetFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextTarget, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextTargetDirFile);
			when(cryptoPathMapper.getCiphertextDirPath(cleartextSource)).thenReturn(ciphertextSourceDir);
			when(cryptoPathMapper.getCiphertextDirPath(cleartextTarget)).thenReturn(ciphertextTargetDir);
		}

		public class Move {

			@Test
			public void moveFileToItselfDoesNothing() throws IOException {
				inTest.move(cleartextSource, cleartextSource);

				verify(readonlyFlag).assertWritable();
				verifyZeroInteractions(cleartextSource);
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
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceDirFile")).when(physicalFsProv).checkAccess(ciphertextSourceDirFile);
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

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).move(ciphertextSourceFile, ciphertextTargetFile, option1, option2);
			}

			@Test
			public void moveDirectoryDontReplaceExisting() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);

				CopyOption option1 = mock(CopyOption.class);
				CopyOption option2 = mock(CopyOption.class);

				inTest.move(cleartextSource, cleartextTarget, option1, option2);

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).move(ciphertextSourceDirFile, ciphertextTargetDirFile, option1, option2);
				verify(dirIdProvider).move(ciphertextSourceDirFile, ciphertextTargetDirFile);
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

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).delete(ciphertextTargetDir);
				verify(physicalFsProv).move(ciphertextSourceDirFile, ciphertextTargetDirFile, StandardCopyOption.REPLACE_EXISTING);
				verify(dirIdProvider).move(ciphertextSourceDirFile, ciphertextTargetDirFile);
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
					verify(readonlyFlag).assertWritable();
					verify(physicalFsProv, Mockito.never()).move(Mockito.any(), Mockito.any(), Mockito.any());
				}
			}

			@Test
			public void moveDirectoryReplaceExistingAtomically() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);

				try {
					thrown.expect(AtomicMoveNotSupportedException.class);
					inTest.move(cleartextSource, cleartextTarget, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
				} finally {
					verify(readonlyFlag).assertWritable();
					verify(physicalFsProv, Mockito.never()).move(Mockito.any(), Mockito.any(), Mockito.any());
				}
			}

		}

		public class Copy {

			private final CryptoPath cleartextTargetParent = mock(CryptoPath.class, "cleartextTargetParent");
			private final Path ciphertextTargetParent = mock(Path.class, "ciphertextTargetParent");
			private final Path ciphertextTargetDirParent = mock(Path.class, "ciphertextTargetDirParent");
			private final FileChannel ciphertextTargetDirFileChannel = mock(FileChannel.class);

			@Before
			public void setup() throws IOException, ReflectiveOperationException {
				when(cleartextTarget.getParent()).thenReturn(cleartextTargetParent);
				when(cryptoPathMapper.getCiphertextDirPath(cleartextTargetParent)).thenReturn(ciphertextTargetParent);
				when(ciphertextTargetDir.getParent()).thenReturn(ciphertextTargetDirParent);
				when(ciphertextTargetParent.getFileSystem()).thenReturn(physicalFs);
				when(ciphertextTargetDir.getFileSystem()).thenReturn(physicalFs);

				when(cryptoPathMapper.getCiphertextDir(cleartextTarget)).thenReturn(new Directory("42", ciphertextTargetDir));
				when(physicalFsProv.newFileChannel(Mockito.same(ciphertextTargetDirFile), Mockito.anySet(), Mockito.any())).thenReturn(ciphertextTargetDirFileChannel);
				Field closeLockField = AbstractInterruptibleChannel.class.getDeclaredField("closeLock");
				closeLockField.setAccessible(true);
				closeLockField.set(ciphertextTargetDirFileChannel, new Object());
			}

			@Test
			public void copyFileToItselfDoesNothing() throws IOException {
				inTest.copy(cleartextSource, cleartextSource);

				verify(readonlyFlag).assertWritable();
				verifyZeroInteractions(cleartextSource);
			}

			@Test
			public void copyNonExistingFile() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceDirFile")).when(physicalFsProv).checkAccess(ciphertextSourceDirFile);

				thrown.expect(NoSuchFileException.class);
				inTest.copy(cleartextSource, cleartextTarget);
			}

			@Test
			public void copyToAlreadyExistingFile() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceDirFile")).when(physicalFsProv).checkAccess(ciphertextSourceDirFile);
				Mockito.doThrow(new FileAlreadyExistsException("ciphertextTargetFile")).when(physicalFsProv).copy(ciphertextSourceFile, ciphertextTargetFile);

				thrown.expect(FileAlreadyExistsException.class);
				inTest.copy(cleartextSource, cleartextTarget);
			}

			@Test
			public void copyFile() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceDirFile")).when(physicalFsProv).checkAccess(ciphertextSourceDirFile);

				CopyOption option1 = mock(CopyOption.class);
				CopyOption option2 = mock(CopyOption.class);

				inTest.copy(cleartextSource, cleartextTarget, option1, option2);

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).copy(ciphertextSourceFile, ciphertextTargetFile, option1, option2);
			}

			@Test
			public void copyDirectory() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetFile")).when(physicalFsProv).checkAccess(ciphertextTargetFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetDirFile")).when(physicalFsProv).checkAccess(ciphertextTargetDirFile);

				inTest.copy(cleartextSource, cleartextTarget);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(ciphertextTargetDirFileChannel).write(any(ByteBuffer.class));
				verify(physicalFsProv).createDirectory(ciphertextTargetDir);
				verify(dirIdProvider, Mockito.never()).delete(Mockito.any());
			}

			@Test
			@SuppressWarnings("unchecked")
			public void copyDirectoryReplaceExisting() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetFile")).when(physicalFsProv).checkAccess(ciphertextTargetFile);
				DirectoryStream<Path> ds = mock(DirectoryStream.class);
				Iterator<Path> iter = mock(Iterator.class);
				when(physicalFsProv.newDirectoryStream(Mockito.same(ciphertextTargetDir), Mockito.any())).thenReturn(ds);
				when(ds.iterator()).thenReturn(iter);
				when(iter.hasNext()).thenReturn(false);

				inTest.copy(cleartextSource, cleartextTarget, StandardCopyOption.REPLACE_EXISTING);

				verify(readonlyFlag).assertWritable();
				verify(ciphertextTargetDirFileChannel, Mockito.never()).write(any(ByteBuffer.class));
				verify(physicalFsProv, Mockito.never()).createDirectory(Mockito.any());
				verify(dirIdProvider, Mockito.never()).delete(Mockito.any());
			}

			@Test
			public void moveDirectoryCopyBasicAttributes() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetFile")).when(physicalFsProv).checkAccess(ciphertextTargetFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetDirFile")).when(physicalFsProv).checkAccess(ciphertextTargetDirFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(new HashSet<>(Arrays.asList(BasicFileAttributeView.class)));
				FileTime lastModifiedTime = FileTime.from(1, TimeUnit.HOURS);
				FileTime lastAccessTime = FileTime.from(2, TimeUnit.HOURS);
				FileTime createTime = FileTime.from(3, TimeUnit.HOURS);
				BasicFileAttributes srcAttrs = mock(BasicFileAttributes.class);
				BasicFileAttributeView dstAttrView = mock(BasicFileAttributeView.class);
				when(srcAttrs.lastModifiedTime()).thenReturn(lastModifiedTime);
				when(srcAttrs.lastAccessTime()).thenReturn(lastAccessTime);
				when(srcAttrs.creationTime()).thenReturn(createTime);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextSourceDir), Mockito.same(BasicFileAttributes.class), Mockito.any())).thenReturn(srcAttrs);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextTargetDir), Mockito.same(BasicFileAttributeView.class), Mockito.any())).thenReturn(dstAttrView);

				inTest.copy(cleartextSource, cleartextTarget, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setTimes(lastModifiedTime, lastAccessTime, createTime);
			}

			@Test
			public void moveDirectoryCopyFileOwnerAttributes() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetFile")).when(physicalFsProv).checkAccess(ciphertextTargetFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetDirFile")).when(physicalFsProv).checkAccess(ciphertextTargetDirFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(new HashSet<>(Arrays.asList(FileOwnerAttributeView.class)));
				UserPrincipal owner = mock(UserPrincipal.class);
				FileOwnerAttributeView srcAttrsView = mock(FileOwnerAttributeView.class);
				FileOwnerAttributeView dstAttrView = mock(FileOwnerAttributeView.class);
				when(srcAttrsView.getOwner()).thenReturn(owner);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextSourceDir), Mockito.same(FileOwnerAttributeView.class), Mockito.any())).thenReturn(srcAttrsView);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextTargetDir), Mockito.same(FileOwnerAttributeView.class), Mockito.any())).thenReturn(dstAttrView);

				inTest.copy(cleartextSource, cleartextTarget, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setOwner(owner);
			}

			@Test
			@SuppressWarnings("unchecked")
			public void moveDirectoryCopyPosixAttributes() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetFile")).when(physicalFsProv).checkAccess(ciphertextTargetFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetDirFile")).when(physicalFsProv).checkAccess(ciphertextTargetDirFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(new HashSet<>(Arrays.asList(PosixFileAttributeView.class)));
				GroupPrincipal group = mock(GroupPrincipal.class);
				Set<PosixFilePermission> permissions = mock(Set.class);
				PosixFileAttributes srcAttrs = mock(PosixFileAttributes.class);
				PosixFileAttributeView dstAttrView = mock(PosixFileAttributeView.class);
				when(srcAttrs.group()).thenReturn(group);
				when(srcAttrs.permissions()).thenReturn(permissions);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextSourceDir), Mockito.same(PosixFileAttributes.class), Mockito.any())).thenReturn(srcAttrs);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextTargetDir), Mockito.same(PosixFileAttributeView.class), Mockito.any())).thenReturn(dstAttrView);

				inTest.copy(cleartextSource, cleartextTarget, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setGroup(group);
				verify(dstAttrView).setPermissions(permissions);
			}

			@Test
			public void moveDirectoryCopyDosAttributes() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetFile")).when(physicalFsProv).checkAccess(ciphertextTargetFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetDirFile")).when(physicalFsProv).checkAccess(ciphertextTargetDirFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(new HashSet<>(Arrays.asList(DosFileAttributeView.class)));
				DosFileAttributes srcAttrs = mock(DosFileAttributes.class);
				DosFileAttributeView dstAttrView = mock(DosFileAttributeView.class);
				when(srcAttrs.isArchive()).thenReturn(true);
				when(srcAttrs.isHidden()).thenReturn(true);
				when(srcAttrs.isReadOnly()).thenReturn(true);
				when(srcAttrs.isSystem()).thenReturn(true);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextSourceDir), Mockito.same(DosFileAttributes.class), Mockito.any())).thenReturn(srcAttrs);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextTargetDir), Mockito.same(DosFileAttributeView.class), Mockito.any())).thenReturn(dstAttrView);

				inTest.copy(cleartextSource, cleartextTarget, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setArchive(true);
				verify(dstAttrView).setHidden(true);
				verify(dstAttrView).setReadOnly(true);
				verify(dstAttrView).setSystem(true);
			}

			@Test
			@SuppressWarnings("unchecked")
			public void moveDirectoryReplaceExistingNonEmpty() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetFile")).when(physicalFsProv).checkAccess(ciphertextTargetFile);
				DirectoryStream<Path> ds = mock(DirectoryStream.class);
				Iterator<Path> iter = mock(Iterator.class);
				when(physicalFsProv.newDirectoryStream(Mockito.same(ciphertextTargetDir), Mockito.any())).thenReturn(ds);
				when(ds.iterator()).thenReturn(iter);
				when(iter.hasNext()).thenReturn(true);

				try {
					thrown.expect(DirectoryNotEmptyException.class);
					inTest.copy(cleartextSource, cleartextTarget, StandardCopyOption.REPLACE_EXISTING);
				} finally {
					verify(readonlyFlag).assertWritable();
					verify(ciphertextTargetDirFileChannel, Mockito.never()).write(any(ByteBuffer.class));
					verify(physicalFsProv, Mockito.never()).createDirectory(Mockito.any());
					verify(dirIdProvider, Mockito.never()).delete(Mockito.any());
				}
			}

			@Test
			public void copyDirectoryToAlreadyExistingDir() throws IOException {
				Mockito.doThrow(new NoSuchFileException("ciphertextSourceFile")).when(physicalFsProv).checkAccess(ciphertextSourceFile);
				Mockito.doThrow(new NoSuchFileException("ciphertextTargetFile")).when(physicalFsProv).checkAccess(ciphertextTargetFile);

				thrown.expect(FileAlreadyExistsException.class);
				inTest.copy(cleartextSource, cleartextTarget);
			}

		}

	}

	public class CreateDirectory {

		private final FileSystemProvider provider = mock(FileSystemProvider.class);
		private final CryptoFileSystemImpl fileSystem = mock(CryptoFileSystemImpl.class);

		@Before
		public void setup() {
			when(fileSystem.provider()).thenReturn(provider);
		}

		@Test
		public void createDirectoryIfPathHasNoParentDoesNothing() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			when(path.getParent()).thenReturn(null);

			inTest.createDirectory(path);

			verify(readonlyFlag).assertWritable();
			verify(path).getParent();
			verifyNoMoreInteractions(path);
		}

		@Test
		public void createDirectoryIfPathsParentDoesNotExistsThrowsNoSuchFileException() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			CryptoPath parent = mock(CryptoPath.class);
			Path cyphertextParent = mock(Path.class);
			when(path.getParent()).thenReturn(parent);
			when(cryptoPathMapper.getCiphertextDirPath(parent)).thenReturn(cyphertextParent);
			when(cyphertextParent.getFileSystem()).thenReturn(fileSystem);
			doThrow(NoSuchFileException.class).when(provider).checkAccess(cyphertextParent);

			thrown.expect(NoSuchFileException.class);
			thrown.expectMessage(parent.toString());

			inTest.createDirectory(path);
		}

		@Test
		public void createDirectoryIfPathCyphertextFileDoesExistThrowsFileAlreadyException() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			CryptoPath parent = mock(CryptoPath.class);
			Path cyphertextParent = mock(Path.class);
			Path cyphertextFile = mock(Path.class);
			when(path.getParent()).thenReturn(parent);
			when(cryptoPathMapper.getCiphertextDirPath(parent)).thenReturn(cyphertextParent);
			when(cryptoPathMapper.getCiphertextFilePath(path, CiphertextFileType.FILE)).thenReturn(cyphertextFile);
			when(cyphertextParent.getFileSystem()).thenReturn(fileSystem);
			when(cyphertextFile.getFileSystem()).thenReturn(fileSystem);

			thrown.expect(FileAlreadyExistsException.class);
			thrown.expectMessage(path.toString());

			inTest.createDirectory(path);
		}

		@Test
		public void createDirectoryCreatesDirectoryIfConditonsAreMet() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			CryptoPath parent = mock(CryptoPath.class);
			Path cyphertextParent = mock(Path.class);
			Path cyphertextFile = mock(Path.class);
			Path cyphertextDirFile = mock(Path.class);
			Path cyphertextDirPath = mock(Path.class);
			String dirId = "DirId1234ABC";
			FileChannelMock channel = new FileChannelMock(100);
			Directory cyphertextDir = new Directory(dirId, cyphertextDirPath);
			when(path.getParent()).thenReturn(parent);
			when(cryptoPathMapper.getCiphertextDirPath(parent)).thenReturn(cyphertextParent);
			when(cryptoPathMapper.getCiphertextFilePath(path, CiphertextFileType.FILE)).thenReturn(cyphertextFile);
			when(cryptoPathMapper.getCiphertextFilePath(path, CiphertextFileType.DIRECTORY)).thenReturn(cyphertextDirFile);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(cyphertextDir);
			when(cyphertextParent.getFileSystem()).thenReturn(fileSystem);
			when(cyphertextFile.getFileSystem()).thenReturn(fileSystem);
			when(cyphertextDirFile.getFileSystem()).thenReturn(fileSystem);
			when(cyphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			when(provider.newFileChannel(cyphertextDirFile, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))).thenReturn(channel);
			doThrow(NoSuchFileException.class).when(provider).checkAccess(cyphertextFile);

			inTest.createDirectory(path);

			verify(readonlyFlag).assertWritable();
			assertThat(channel.data(), is(contains(dirId.getBytes(UTF_8))));
		}

		@Test
		public void createDirectoryClearsDirIdAndDeletesDirFileIfCreatingDirFails() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			CryptoPath parent = mock(CryptoPath.class);
			Path ciphertextParent = mock(Path.class, "ciphertextParent");
			Path ciphertextFile = mock(Path.class, "ciphertextFile");
			Path ciphertextDirFile = mock(Path.class, "ciphertextDirFile");
			Path ciphertextDirPath = mock(Path.class, "ciphertextDir");
			String dirId = "DirId1234ABC";
			FileChannelMock channel = new FileChannelMock(100);
			Directory ciphertextDir = new Directory(dirId, ciphertextDirPath);
			when(path.getParent()).thenReturn(parent);
			when(cryptoPathMapper.getCiphertextDirPath(parent)).thenReturn(ciphertextParent);
			when(cryptoPathMapper.getCiphertextFilePath(path, CiphertextFileType.FILE)).thenReturn(ciphertextFile);
			when(cryptoPathMapper.getCiphertextFilePath(path, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextDirFile);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(ciphertextDir);
			when(ciphertextParent.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextFile.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirFile.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			doThrow(new NoSuchFileException("ciphertextFile")).when(provider).checkAccess(ciphertextFile);
			when(provider.newFileChannel(ciphertextDirFile, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))).thenReturn(channel);

			// make createDirectory with an FileSystemException during Files.createDirectories(ciphertextDirPath)
			doThrow(new IOException()).when(provider).createDirectory(ciphertextDirPath);
			when(ciphertextDirPath.toAbsolutePath()).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getParent()).thenReturn(null);
			thrown.expect(IOException.class);

			try {
				inTest.createDirectory(path);
			} finally {
				verify(readonlyFlag).assertWritable();
				verify(provider).delete(ciphertextDirFile);
				verify(dirIdProvider).delete(ciphertextDirFile);
			}
		}

	}

	public class IsHidden {

		private final FileSystemProvider provider = mock(FileSystemProvider.class);
		private final CryptoFileSystemImpl fileSystem = mock(CryptoFileSystemImpl.class);

		@Before
		public void setup() {
			when(fileSystem.provider()).thenReturn(provider);
		}

		@Test
		public void isHiddenReturnsFalseIfDosFileAttributeViewIsNotAvailable() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);

			assertThat(inTest.isHidden(path), is(false));
		}

		@Test
		public void isHiddenReturnsTrueIfDosFileAttributeViewIsAvailableAndIsHiddenIsTrue() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			DosFileAttributeView fileAttributeView = mock(DosFileAttributeView.class);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributeView.readAttributes()).thenReturn(fileAttributes);
			when(fileAttributes.isHidden()).thenReturn(true);
			when(fileAttributeViewProvider.getAttributeView(ciphertextDirPath, DosFileAttributeView.class)).thenReturn(fileAttributeView);

			assertThat(inTest.isHidden(path), is(true));
		}

		@Test
		public void isHiddenReturnsFalseIfDosFileAttributeViewIsAvailableAndIsHiddenIsFalse() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			DosFileAttributeView fileAttributeView = mock(DosFileAttributeView.class);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributeView.readAttributes()).thenReturn(fileAttributes);
			when(fileAttributes.isHidden()).thenReturn(false);
			when(fileAttributeViewProvider.getAttributeView(ciphertextDirPath, DosFileAttributeView.class)).thenReturn(fileAttributeView);

			assertThat(inTest.isHidden(path), is(false));
		}

	}

	public class CheckAccess {

		private final FileSystemProvider provider = mock(FileSystemProvider.class);
		private final CryptoFileSystemImpl fileSystem = mock(CryptoFileSystemImpl.class);

		@Before
		public void setup() {
			when(fileSystem.provider()).thenReturn(provider);
		}

		@Test
		public void readsBasicAttributesIfNeitherPosixNorDosFileAttributeViewIsSupported() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);

			inTest.checkAccess(path);
		}

		@Test
		public void throwsExceptionFromReadBasicAttributesIfNeitherPosixNorDosFileAttributeViewIsSupported() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			IOException expectedException = new IOException();
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, BasicFileAttributes.class)).thenThrow(expectedException);

			thrown.expect(is(expectedException));

			inTest.checkAccess(path);
		}

		@Test
		public void throwsExceptionFromReadDosAttributesIfDosFileAttributeViewIsSupported() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			IOException expectedException = new IOException();
			when(fileStore.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, DosFileAttributes.class)).thenThrow(expectedException);

			thrown.expect(is(expectedException));

			inTest.checkAccess(path);
		}

		@Test
		public void succeedsIfDosFileAttributeViewIsSupportedAndFileIsReadOnlyAndWritePermissionIsNotChecked() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			when(fileStore.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributes.isReadOnly()).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, DosFileAttributes.class)).thenReturn(fileAttributes);

			inTest.checkAccess(path);
		}

		@Test
		public void succeedsIfDosFileAttributeViewIsSupportedAndFileIsNotReadOnlyAndWritePermissionIsChecked() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			when(fileStore.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributes.isReadOnly()).thenReturn(false);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, DosFileAttributes.class)).thenReturn(fileAttributes);

			inTest.checkAccess(path, AccessMode.WRITE);
		}

		@Test
		public void failsIfDosFileAttributeViewIsSupportedAndFileIsReadOnlyAndWritePermissionIsChecked() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			when(fileStore.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributes.isReadOnly()).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, DosFileAttributes.class)).thenReturn(fileAttributes);

			thrown.expect(AccessDeniedException.class);
			thrown.expectMessage(path.toString());
			thrown.expectMessage("read only file");

			inTest.checkAccess(path, AccessMode.WRITE);
		}

		@Test
		public void throwsExceptionFromReadPosixAttributesIfPosixFileAttributeViewIsSupported() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			IOException expectedException = new IOException();
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, PosixFileAttributes.class)).thenThrow(expectedException);

			thrown.expect(is(expectedException));

			inTest.checkAccess(path);
		}

		@Test
		public void succeedsIfPosixFileAttributeViewIsSupportedAndNoAccessModeIsChecked() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, PosixFileAttributes.class)).thenReturn(fileAttributes);

			inTest.checkAccess(path);
		}

		@Test
		public void failsIfPosixFileAttributeViewIsSupportedAndReadAccessModeIsCheckedButNotSupported() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, PosixFileAttributes.class)).thenReturn(fileAttributes);

			thrown.expect(AccessDeniedException.class);
			thrown.expectMessage(path.toString());

			inTest.checkAccess(path, AccessMode.READ);
		}

		@Test
		public void failsIfPosixFileAttributeViewIsSupportedAndWriteAccessModeIsCheckedButNotSupported() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, PosixFileAttributes.class)).thenReturn(fileAttributes);

			thrown.expect(AccessDeniedException.class);
			thrown.expectMessage(path.toString());

			inTest.checkAccess(path, AccessMode.WRITE);
		}

		@Test
		public void failsIfPosixFileAttributeViewIsSupportedAndExecuteAccessModeIsCheckedButNotSupported() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, PosixFileAttributes.class)).thenReturn(fileAttributes);

			thrown.expect(AccessDeniedException.class);
			thrown.expectMessage(path.toString());

			inTest.checkAccess(path, AccessMode.EXECUTE);
		}

		@Test
		public void succeedsIfPosixFileAttributeViewIsSupportedAndReadAccessModeIsCheckedAndSupported() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, PosixFileAttributes.class)).thenReturn(fileAttributes);
			when(fileAttributes.permissions()).thenReturn(Collections.singleton(PosixFilePermission.OWNER_READ));

			inTest.checkAccess(path, AccessMode.READ);
		}

		@Test
		public void succeedsIfPosixFileAttributeViewIsSupportedAndWriteAccessModeIsCheckedAndSupported() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, PosixFileAttributes.class)).thenReturn(fileAttributes);
			when(fileAttributes.permissions()).thenReturn(Collections.singleton(PosixFilePermission.OWNER_WRITE));

			inTest.checkAccess(path, AccessMode.WRITE);
		}

		@Test
		public void succeedsIfPosixFileAttributeViewIsSupportedAndExecuteAccessModeIsCheckedAndSupported() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(ciphertextDirPath, PosixFileAttributes.class)).thenReturn(fileAttributes);
			when(fileAttributes.permissions()).thenReturn(Collections.singleton(PosixFilePermission.OWNER_EXECUTE));

			inTest.checkAccess(path, AccessMode.EXECUTE);
		}

		/**
		 * This test ensures, that we get test failures if the {@link AccessMode AccessModes} are extended.
		 * This would allow us to handle the new values in checkAccess accordingly.
		 */
		@Test
		public void testAccessModeContainsOnlyKnownValues() {
			assertThat(EnumSet.allOf(AccessMode.class), containsInAnyOrder(AccessMode.READ, AccessMode.WRITE, AccessMode.EXECUTE));
		}

	}

	public class SetAttribute {

		private final FileSystemProvider provider = mock(FileSystemProvider.class);
		private final CryptoFileSystemImpl fileSystem = mock(CryptoFileSystemImpl.class);

		@Before
		public void setup() {
			when(fileSystem.provider()).thenReturn(provider);
		}

		@Test
		public void setAttributeOnRegularDirectory() throws IOException {
			String name = "nameTest123";
			Object value = new Object();
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);

			inTest.setAttribute(path, name, value);

			verify(readonlyFlag).assertWritable();
			verify(fileAttributeByNameProvider).setAttribute(ciphertextDirPath, name, value);
		}

		@Test
		public void setAttributeOnNonExistingRootDirectory() throws IOException {
			String name = "nameTest123";
			Object value = new Object();
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			doThrow(new NoSuchFileException("")).when(provider).checkAccess(ciphertextDirPath);
			when(path.getNameCount()).thenReturn(0);

			inTest.setAttribute(path, name, value);

			verify(readonlyFlag).assertWritable();
			verify(fileAttributeByNameProvider).setAttribute(ciphertextDirPath, name, value);
		}

		@Test
		public void setAttributeOnFile() throws IOException {
			String name = "nameTest123";
			Object value = new Object();
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			Path ciphertextFilePath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDirPath(path)).thenReturn(ciphertextDirPath);
			when(cryptoPathMapper.getCiphertextFilePath(path, CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextFilePath.getFileSystem()).thenReturn(fileSystem);
			doThrow(new NoSuchFileException("")).when(provider).checkAccess(ciphertextDirPath);
			when(path.getNameCount()).thenReturn(1);

			inTest.setAttribute(path, name, value);

			verify(readonlyFlag).assertWritable();
			verify(fileAttributeByNameProvider).setAttribute(ciphertextFilePath, name, value);
		}

	}

}
