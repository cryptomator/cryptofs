package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType;
import org.cryptomator.cryptofs.attr.AttributeByNameProvider;
import org.cryptomator.cryptofs.attr.AttributeProvider;
import org.cryptomator.cryptofs.attr.AttributeViewProvider;
import org.cryptomator.cryptofs.attr.AttributeViewType;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles.TwoPhaseMove;
import org.cryptomator.cryptofs.mocks.FileChannelMock;
import org.cryptomator.cryptolib.api.Cryptor;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

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
import java.nio.file.LinkOption;
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
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.atLeast;

public class CryptoFileSystemImplTest {

	private final Path pathToVault = mock(Path.class);
	private final Cryptor cryptor = mock(Cryptor.class);
	private final CryptoFileSystemProvider provider = mock(CryptoFileSystemProvider.class);
	private final CryptoFileSystems cryptoFileSystems = mock(CryptoFileSystems.class);
	private final CryptoFileStore fileStore = mock(CryptoFileStore.class);
	private final OpenCryptoFiles openCryptoFiles = mock(OpenCryptoFiles.class);
	private final Symlinks symlinks = mock(Symlinks.class);
	private final CryptoPathMapper cryptoPathMapper = mock(CryptoPathMapper.class);
	private final DirectoryIdProvider dirIdProvider = mock(DirectoryIdProvider.class);
	private final AttributeProvider fileAttributeProvider = mock(AttributeProvider.class);
	private final AttributeByNameProvider fileAttributeByNameProvider = mock(AttributeByNameProvider.class);
	private final AttributeViewProvider fileAttributeViewProvider = mock(AttributeViewProvider.class);
	private final PathMatcherFactory pathMatcherFactory = mock(PathMatcherFactory.class);
	private final CryptoPathFactory cryptoPathFactory = mock(CryptoPathFactory.class);
	private final CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);
	private final RootDirectoryInitializer rootDirectoryInitializer = mock(RootDirectoryInitializer.class);
	private final DirectoryStreamFactory directoryStreamFactory = mock(DirectoryStreamFactory.class);
	private final FinallyUtil finallyUtil = mock(FinallyUtil.class);
	private final CiphertextDirectoryDeleter ciphertextDirDeleter = mock(CiphertextDirectoryDeleter.class);
	private final ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);

	private final CryptoPath root = mock(CryptoPath.class);
	private final CryptoPath empty = mock(CryptoPath.class);

	private CryptoFileSystemImpl inTest;

	@BeforeEach
	public void setup() {
		when(cryptoPathFactory.rootFor(any())).thenReturn(root);
		when(cryptoPathFactory.emptyFor(any())).thenReturn(empty);

		inTest = new CryptoFileSystemImpl(provider, cryptoFileSystems, pathToVault, cryptor,
				fileStore, stats, cryptoPathMapper, cryptoPathFactory,
				pathMatcherFactory, directoryStreamFactory, dirIdProvider,
				fileAttributeProvider, fileAttributeByNameProvider, fileAttributeViewProvider,
				openCryptoFiles, symlinks, finallyUtil, ciphertextDirDeleter, readonlyFlag, rootDirectoryInitializer);
	}

	@Test
	public void testProviderReturnsProvider() {
		Assertions.assertSame(provider, inTest.provider());
	}

	@Test
	public void testEmptyPathReturnsEmptyPath() {
		Assertions.assertSame(empty, inTest.getEmptyPath());
	}

	@Test
	public void testGetStatsReturnsStats() {
		Assertions.assertSame(stats, inTest.getStats());
	}

	@Test
	public void testToStringWithOpenFileSystem() {
		Assertions.assertEquals("CryptoFileSystem(" + pathToVault.toString() + ")", inTest.toString());
	}

	@Test
	public void testToStringWithClosedFileSystem() throws IOException {
		inTest.close();

		Assertions.assertEquals("closed CryptoFileSystem(" + pathToVault.toString() + ")", inTest.toString());
	}

	@Test
	public void testGetFilestoresReturnsIterableContainingFileStore() {
		MatcherAssert.assertThat(inTest.getFileStores(), contains(fileStore));
	}

	@Test
	public void testIsReadOnlyReturnsTrueIfReadonlyFlagIsSet() {
		when(readonlyFlag.isSet()).thenReturn(true);

		Assertions.assertTrue(inTest.isReadOnly());
	}

	@Test
	public void testIsReadOnlyReturnsFalseIfReadonlyFlagIsNotSet() {
		when(readonlyFlag.isSet()).thenReturn(false);

		Assertions.assertFalse(inTest.isReadOnly());
	}

	@Test
	public void testGetSeparatorReturnsSlash() {
		Assertions.assertEquals("/", inTest.getSeparator());
	}

	@Test
	public void testGetRootDirectoriesReturnsRoot() {
		MatcherAssert.assertThat(inTest.getRootDirectories(), containsInAnyOrder(root));
	}

	@Test
	public void testGetFileStoresReturnsFileStore() {
		Assertions.assertSame(fileStore, inTest.getFileStore());
	}

	@Nested
	public class CloseAndIsOpen {

		@SuppressWarnings("unchecked")
		@BeforeEach
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
			Assertions.assertTrue(inTest.isOpen());
		}

		@Test
		public void testIsOpenReturnsFalseWhenClosed() throws IOException {
			inTest.close();

			Assertions.assertFalse(inTest.isOpen());
		}

		@Test
		public void testAssertOpenThrowsClosedFileSystemExceptionWhenClosed() throws IOException {
			inTest.close();

			Assertions.assertThrows(ClosedFileSystemException.class, () -> {
				inTest.assertOpen();
			});
		}

	}

	@Nested
	public class DuplicateCloseAndIsOpen {

		@SuppressWarnings("unchecked")
		@BeforeEach
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

			Assertions.assertFalse(inTest.isOpen());
		}

	}

	@Test // TODO markuskreusch: is this behaviour correct?
	public void testSupportedFileAttributeViewsDelegatesToFileSystemOfVaultLocation() {
		when(fileStore.supportedFileAttributeViewTypes()).thenReturn(EnumSet.of(AttributeViewType.BASIC));

		Set<String> result = inTest.supportedFileAttributeViews();
		MatcherAssert.assertThat(result, CoreMatchers.hasItem("basic"));
	}

	@Test
	public void testGetPathDelegatesToCryptoPathFactory() {
		CryptoPath expected = mock(CryptoPath.class);
		String first = "abc";
		String[] more = {"cde", "efg"};
		when(cryptoPathFactory.getPath(inTest, first, more)).thenReturn(expected);

		Assertions.assertSame(expected, inTest.getPath(first, more));
	}

	@Test
	public void testGetPathMatcherDelegatesToPathMatcherFactory() {
		PathMatcher expected = mock(PathMatcher.class);
		String syntaxAndPattern = "asd";
		when(pathMatcherFactory.pathMatcherFrom(syntaxAndPattern)).thenReturn(expected);

		Assertions.assertEquals(expected, inTest.getPathMatcher(syntaxAndPattern));
	}

	@Test
	public void testGetUserPrincipalLookupServiceThrowsUnsupportedOperationException() {
		Assertions.assertThrows(UnsupportedOperationException.class, () -> {
			inTest.getUserPrincipalLookupService();
		});
	}

	@Test
	public void testNewWatchServiceThrowsUnsupportedOperationException() throws IOException {
		Assertions.assertThrows(UnsupportedOperationException.class, () -> {
			inTest.newWatchService();
		});
	}

	@Nested
	public class Delete {

		private final CryptoPath cleartextPath = mock(CryptoPath.class, "cleartext");
		private final Path ciphertextFilePath = mock(Path.class, "ciphertextFile");
		private final Path ciphertextDirFilePath = mock(Path.class, "ciphertextDirFile");
		private final Path ciphertextDirPath = mock(Path.class, "ciphertextDir");
		private final FileSystem physicalFs = mock(FileSystem.class);
		private final FileSystemProvider physicalFsProv = mock(FileSystemProvider.class);

		@BeforeEach
		public void setup() throws IOException {
			when(ciphertextFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirPath.getFileSystem()).thenReturn(physicalFs);
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextDirFilePath);
			when(cryptoPathMapper.getCiphertextDir(cleartextPath)).thenReturn(new CiphertextDirectory("foo", ciphertextDirPath));
		}

		@Test
		public void testDeleteExistingFile() throws IOException {
			when(cryptoPathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.FILE);
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(true);

			inTest.delete(cleartextPath);

			verify(readonlyFlag).assertWritable();
			verify(physicalFsProv).deleteIfExists(ciphertextFilePath);
		}

		@Test
		public void testDeleteExistingDirectory() throws IOException {
			when(cryptoPathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.DIRECTORY);
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(false);

			inTest.delete(cleartextPath);
			verify(ciphertextDirDeleter).deleteCiphertextDirIncludingNonCiphertextFiles(ciphertextDirPath, cleartextPath);
			verify(readonlyFlag).assertWritable();
			verify(physicalFsProv).deleteIfExists(ciphertextDirFilePath);
			verify(dirIdProvider).delete(ciphertextDirFilePath);
			verify(cryptoPathMapper).invalidatePathMapping(cleartextPath);
		}

		@Test
		public void testDeleteNonExistingFileOrDir() throws IOException {
			when(cryptoPathMapper.getCiphertextFileType(cleartextPath)).thenThrow(NoSuchFileException.class);

			Assertions.assertThrows(NoSuchFileException.class, () -> {
				inTest.delete(cleartextPath);
			});
		}

		@Test
		public void testDeleteNonEmptyDir() throws IOException {
			when(cryptoPathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.DIRECTORY);
			when(physicalFsProv.deleteIfExists(ciphertextFilePath)).thenReturn(false);
			Mockito.doThrow(new DirectoryNotEmptyException("ciphertextDir")).when(ciphertextDirDeleter).deleteCiphertextDirIncludingNonCiphertextFiles(ciphertextDirPath, cleartextPath);

			Assertions.assertThrows(DirectoryNotEmptyException.class, () -> {
				inTest.delete(cleartextPath);
			});
		}

	}

	@Nested
	public class CopyAndMove {

		private final CryptoPath cleartextSource = mock(CryptoPath.class, "cleartextSource");
		private final CryptoPath sourceLinkTarget = mock(CryptoPath.class, "sourceLinkTarget");
		private final CryptoPath cleartextDestination = mock(CryptoPath.class, "cleartextDestination");
		private final CryptoPath destinationLinkTarget = mock(CryptoPath.class, "destinationLinkTarget");
		private final Path ciphertextSourceFile = mock(Path.class, "ciphertextSourceFile");
		private final Path ciphertextSourceDirFile = mock(Path.class, "ciphertextSourceDirFile");
		private final Path ciphertextSourceDir = mock(Path.class, "ciphertextSourceDir");
		private final Path ciphertextDestinationFile = mock(Path.class, "ciphertextDestinationFile");
		private final Path ciphertextDestinationDirFile = mock(Path.class, "ciphertextDestinationDirFile");
		private final Path ciphertextDestinationDir = mock(Path.class, "ciphertextDestinationDir");
		private final FileSystem physicalFs = mock(FileSystem.class);
		private final FileSystemProvider physicalFsProv = mock(FileSystemProvider.class);

		@BeforeEach
		public void setup() throws IOException {
			when(ciphertextSourceFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextSourceDirFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextSourceDir.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDestinationFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDestinationDirFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDestinationDir.getFileSystem()).thenReturn(physicalFs);
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.FILE)).thenReturn(ciphertextSourceFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextSourceDirFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.SYMLINK)).thenReturn(ciphertextSourceFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextDestination, CiphertextFileType.FILE)).thenReturn(ciphertextDestinationFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextDestination, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextDestinationDirFile);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextDestination, CiphertextFileType.SYMLINK)).thenReturn(ciphertextDestinationFile);
			when(cryptoPathMapper.getCiphertextDir(cleartextSource)).thenReturn(new CiphertextDirectory("foo", ciphertextSourceDir));
			when(cryptoPathMapper.getCiphertextDir(cleartextDestination)).thenReturn(new CiphertextDirectory("bar", ciphertextDestinationDir));
			when(symlinks.resolveRecursively(cleartextSource)).thenReturn(sourceLinkTarget);
			when(symlinks.resolveRecursively(cleartextDestination)).thenReturn(destinationLinkTarget);
			when(cryptoPathMapper.getCiphertextFileType(sourceLinkTarget)).thenReturn(CiphertextFileType.FILE);
			when(cryptoPathMapper.getCiphertextFileType(destinationLinkTarget)).thenReturn(CiphertextFileType.FILE);
			when(cryptoPathMapper.getCiphertextFilePath(sourceLinkTarget, CiphertextFileType.FILE)).thenReturn(ciphertextSourceFile);
			when(cryptoPathMapper.getCiphertextFilePath(destinationLinkTarget, CiphertextFileType.FILE)).thenReturn(ciphertextDestinationFile);
		}

		@Nested
		public class Move {

			@Test
			public void moveFileToItselfDoesNothing() throws IOException {
				inTest.move(cleartextSource, cleartextSource);

				verify(readonlyFlag).assertWritable();
				verifyZeroInteractions(cleartextSource);
			}

			@Test
			public void moveNonExistingFile() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenThrow(NoSuchFileException.class);

				Assertions.assertThrows(NoSuchFileException.class, () -> {
					inTest.move(cleartextSource, cleartextDestination);
				});
			}

			@Test
			public void moveToAlreadyExistingFile() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.FILE);
				doThrow(new FileAlreadyExistsException(cleartextDestination.toString())).when(cryptoPathMapper).assertNonExisting(cleartextDestination);

				Assertions.assertThrows(FileAlreadyExistsException.class, () -> {
					inTest.move(cleartextSource, cleartextDestination);
				});
			}

			@Test
			public void moveSymlink() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.SYMLINK);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				TwoPhaseMove openFileMove = Mockito.mock(TwoPhaseMove.class);
				Mockito.when(openCryptoFiles.prepareMove(ciphertextSourceFile, ciphertextDestinationFile)).thenReturn(openFileMove);

				CopyOption option1 = mock(CopyOption.class);
				CopyOption option2 = mock(CopyOption.class);

				inTest.move(cleartextSource, cleartextDestination, option1, option2);

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).move(ciphertextSourceFile, ciphertextDestinationFile, option1, option2);
				verify(openFileMove).commit();
			}

			@Test
			public void moveFile() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.FILE);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				TwoPhaseMove openFileMove = Mockito.mock(TwoPhaseMove.class);
				Mockito.when(openCryptoFiles.prepareMove(ciphertextSourceFile, ciphertextDestinationFile)).thenReturn(openFileMove);

				CopyOption option1 = mock(CopyOption.class);
				CopyOption option2 = mock(CopyOption.class);

				inTest.move(cleartextSource, cleartextDestination, option1, option2);

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).move(ciphertextSourceFile, ciphertextDestinationFile, option1, option2);
				verify(openFileMove).commit();
			}

			@Test
			public void moveDirectoryDontReplaceExisting() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);

				CopyOption option1 = mock(CopyOption.class);
				CopyOption option2 = mock(CopyOption.class);

				inTest.move(cleartextSource, cleartextDestination, option1, option2);

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).move(ciphertextSourceDirFile, ciphertextDestinationDirFile, option1, option2);
				verify(dirIdProvider).move(ciphertextSourceDirFile, ciphertextDestinationDirFile);
				verify(cryptoPathMapper).invalidatePathMapping(cleartextSource);
			}

			@Test
			@SuppressWarnings("unchecked")
			public void moveDirectoryReplaceExisting() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenReturn(CiphertextFileType.DIRECTORY);
				DirectoryStream<Path> ds = mock(DirectoryStream.class);
				Iterator<Path> iter = mock(Iterator.class);
				when(physicalFsProv.newDirectoryStream(Mockito.same(ciphertextDestinationDir), Mockito.any())).thenReturn(ds);
				when(ds.iterator()).thenReturn(iter);
				when(iter.hasNext()).thenReturn(false);

				inTest.move(cleartextSource, cleartextDestination, StandardCopyOption.REPLACE_EXISTING);

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).delete(ciphertextDestinationDir);
				verify(physicalFsProv).move(ciphertextSourceDirFile, ciphertextDestinationDirFile, StandardCopyOption.REPLACE_EXISTING);
				verify(dirIdProvider).move(ciphertextSourceDirFile, ciphertextDestinationDirFile);
				verify(cryptoPathMapper).invalidatePathMapping(cleartextSource);
			}

			@Test
			@SuppressWarnings("unchecked")
			public void moveDirectoryReplaceExistingNonEmpty() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenReturn(CiphertextFileType.DIRECTORY);

				DirectoryStream<Path> ds = mock(DirectoryStream.class);
				Iterator<Path> iter = mock(Iterator.class);
				when(physicalFsProv.newDirectoryStream(Mockito.same(ciphertextDestinationDir), Mockito.any())).thenReturn(ds);
				when(ds.iterator()).thenReturn(iter);
				when(iter.hasNext()).thenReturn(true);

				Assertions.assertThrows(DirectoryNotEmptyException.class, () -> {
					inTest.move(cleartextSource, cleartextDestination, StandardCopyOption.REPLACE_EXISTING);
				});
				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv, Mockito.never()).move(Mockito.any(), Mockito.any(), Mockito.any());
			}

			@Test
			public void moveDirectoryReplaceExistingAtomically() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenReturn(CiphertextFileType.DIRECTORY);

				Assertions.assertThrows(AtomicMoveNotSupportedException.class, () -> {
					inTest.move(cleartextSource, cleartextDestination, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
				});
				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv, Mockito.never()).move(Mockito.any(), Mockito.any(), Mockito.any());
			}

		}

		@Nested
		public class Copy {

			private final CryptoPath cleartextTargetParent = mock(CryptoPath.class, "cleartextTargetParent");
			private final Path ciphertextTargetParent = mock(Path.class, "ciphertextTargetParent");
			private final Path ciphertextTargetDirParent = mock(Path.class, "ciphertextTargetDirParent");
			private final FileChannel ciphertextTargetDirFileChannel = mock(FileChannel.class);

			@BeforeEach
			public void setup() throws IOException, ReflectiveOperationException {
				when(cleartextDestination.getParent()).thenReturn(cleartextTargetParent);
				when(ciphertextDestinationDir.getParent()).thenReturn(ciphertextTargetDirParent);
				when(ciphertextTargetParent.getFileSystem()).thenReturn(physicalFs);
				when(ciphertextDestinationDir.getFileSystem()).thenReturn(physicalFs);

				when(cryptoPathMapper.getCiphertextDir(cleartextTargetParent)).thenReturn(new CiphertextDirectory("41", ciphertextTargetParent));
				when(cryptoPathMapper.getCiphertextDir(cleartextDestination)).thenReturn(new CiphertextDirectory("42", ciphertextDestinationDir));
				when(physicalFsProv.newFileChannel(Mockito.same(ciphertextDestinationDirFile), Mockito.anySet(), Mockito.any())).thenReturn(ciphertextTargetDirFileChannel);
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
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenThrow(NoSuchFileException.class);

				Assertions.assertThrows(NoSuchFileException.class, () -> {
					inTest.copy(cleartextSource, cleartextDestination);
				});
			}

			@Test
			public void copyToAlreadyExistingFile() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.FILE);
				doThrow(new FileAlreadyExistsException(cleartextDestination.toString())).when(cryptoPathMapper).assertNonExisting(cleartextDestination);

				Assertions.assertThrows(FileAlreadyExistsException.class, () -> {
					inTest.copy(cleartextSource, cleartextDestination);
				});
			}

			@Test
			public void copySymlink() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.SYMLINK);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);

				CopyOption option1 = mock(CopyOption.class);
				CopyOption option2 = mock(CopyOption.class);

				inTest.copy(cleartextSource, cleartextDestination, LinkOption.NOFOLLOW_LINKS, option1, option2);

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).copy(ciphertextSourceFile, ciphertextDestinationFile, option1, option2);
			}

			@Test
			public void copySymlinkTarget() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.SYMLINK);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);

				CopyOption option1 = mock(CopyOption.class);
				CopyOption option2 = mock(CopyOption.class);

				inTest.copy(cleartextSource, cleartextDestination, option1, option2);

				verify(readonlyFlag, Mockito.atLeastOnce()).assertWritable();
				verify(physicalFsProv).copy(ciphertextSourceFile, ciphertextDestinationFile, option1, option2, LinkOption.NOFOLLOW_LINKS);
			}

			@Test
			public void copyFile() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.FILE);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);

				CopyOption option1 = mock(CopyOption.class);
				CopyOption option2 = mock(CopyOption.class);

				inTest.copy(cleartextSource, cleartextDestination, option1, option2);

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).copy(ciphertextSourceFile, ciphertextDestinationFile, option1, option2);
			}

			@Test
			public void copyDirectory() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				Mockito.doThrow(new NoSuchFileException("ciphertextDestinationDirFile")).when(physicalFsProv).checkAccess(ciphertextDestinationDirFile);

				inTest.copy(cleartextSource, cleartextDestination);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(ciphertextTargetDirFileChannel).write(any(ByteBuffer.class));
				verify(physicalFsProv).createDirectory(ciphertextDestinationDir);
				verify(dirIdProvider, Mockito.never()).delete(Mockito.any());
				verify(cryptoPathMapper, Mockito.never()).invalidatePathMapping(Mockito.any());
			}

			@Test
			@SuppressWarnings("unchecked")
			public void copyDirectoryReplaceExisting() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenReturn(CiphertextFileType.DIRECTORY);
				DirectoryStream<Path> ds = mock(DirectoryStream.class);
				Iterator<Path> iter = mock(Iterator.class);
				when(physicalFsProv.newDirectoryStream(Mockito.same(ciphertextDestinationDir), Mockito.any())).thenReturn(ds);
				when(ds.iterator()).thenReturn(iter);
				when(iter.hasNext()).thenReturn(false);

				inTest.copy(cleartextSource, cleartextDestination, StandardCopyOption.REPLACE_EXISTING);

				verify(readonlyFlag).assertWritable();
				verify(ciphertextTargetDirFileChannel, Mockito.never()).write(any(ByteBuffer.class));
				verify(physicalFsProv, Mockito.never()).createDirectory(Mockito.any());
				verify(dirIdProvider, Mockito.never()).delete(Mockito.any());
				verify(cryptoPathMapper, Mockito.never()).invalidatePathMapping(Mockito.any());
			}

			@Test
			public void moveDirectoryCopyBasicAttributes() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				Mockito.doThrow(new NoSuchFileException("ciphertextDestinationDirFile")).when(physicalFsProv).checkAccess(ciphertextDestinationDirFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(EnumSet.of(AttributeViewType.BASIC));
				FileTime lastModifiedTime = FileTime.from(1, TimeUnit.HOURS);
				FileTime lastAccessTime = FileTime.from(2, TimeUnit.HOURS);
				FileTime createTime = FileTime.from(3, TimeUnit.HOURS);
				BasicFileAttributes srcAttrs = mock(BasicFileAttributes.class);
				BasicFileAttributeView dstAttrView = mock(BasicFileAttributeView.class);
				when(srcAttrs.lastModifiedTime()).thenReturn(lastModifiedTime);
				when(srcAttrs.lastAccessTime()).thenReturn(lastAccessTime);
				when(srcAttrs.creationTime()).thenReturn(createTime);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextSourceDir), Mockito.same(BasicFileAttributes.class), Mockito.any())).thenReturn(srcAttrs);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextDestinationDir), Mockito.same(BasicFileAttributeView.class), Mockito.any())).thenReturn(dstAttrView);

				inTest.copy(cleartextSource, cleartextDestination, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setTimes(lastModifiedTime, lastAccessTime, createTime);
			}

			@Test
			public void moveDirectoryCopyFileOwnerAttributes() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				Mockito.doThrow(new NoSuchFileException("ciphertextDestinationDirFile")).when(physicalFsProv).checkAccess(ciphertextDestinationDirFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(EnumSet.of(AttributeViewType.OWNER));
				UserPrincipal owner = mock(UserPrincipal.class);
				FileOwnerAttributeView srcAttrsView = mock(FileOwnerAttributeView.class);
				FileOwnerAttributeView dstAttrView = mock(FileOwnerAttributeView.class);
				when(srcAttrsView.getOwner()).thenReturn(owner);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextSourceDir), Mockito.same(FileOwnerAttributeView.class), Mockito.any())).thenReturn(srcAttrsView);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextDestinationDir), Mockito.same(FileOwnerAttributeView.class), Mockito.any())).thenReturn(dstAttrView);

				inTest.copy(cleartextSource, cleartextDestination, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setOwner(owner);
			}

			@Test
			@SuppressWarnings("unchecked")
			public void moveDirectoryCopyPosixAttributes() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				Mockito.doThrow(new NoSuchFileException("ciphertextDestinationDirFile")).when(physicalFsProv).checkAccess(ciphertextDestinationDirFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(EnumSet.of(AttributeViewType.POSIX));
				GroupPrincipal group = mock(GroupPrincipal.class);
				Set<PosixFilePermission> permissions = mock(Set.class);
				PosixFileAttributes srcAttrs = mock(PosixFileAttributes.class);
				PosixFileAttributeView dstAttrView = mock(PosixFileAttributeView.class);
				when(srcAttrs.group()).thenReturn(group);
				when(srcAttrs.permissions()).thenReturn(permissions);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextSourceDir), Mockito.same(PosixFileAttributes.class), Mockito.any())).thenReturn(srcAttrs);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextDestinationDir), Mockito.same(PosixFileAttributeView.class), Mockito.any())).thenReturn(dstAttrView);

				inTest.copy(cleartextSource, cleartextDestination, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setGroup(group);
				verify(dstAttrView).setPermissions(permissions);
			}

			@Test
			public void moveDirectoryCopyDosAttributes() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				Mockito.doThrow(new NoSuchFileException("ciphertextDestinationDirFile")).when(physicalFsProv).checkAccess(ciphertextDestinationDirFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(EnumSet.of(AttributeViewType.DOS));
				DosFileAttributes srcAttrs = mock(DosFileAttributes.class);
				DosFileAttributeView dstAttrView = mock(DosFileAttributeView.class);
				when(srcAttrs.isArchive()).thenReturn(true);
				when(srcAttrs.isHidden()).thenReturn(true);
				when(srcAttrs.isReadOnly()).thenReturn(true);
				when(srcAttrs.isSystem()).thenReturn(true);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextSourceDir), Mockito.same(DosFileAttributes.class), Mockito.any())).thenReturn(srcAttrs);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextDestinationDir), Mockito.same(DosFileAttributeView.class), Mockito.any())).thenReturn(dstAttrView);

				inTest.copy(cleartextSource, cleartextDestination, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setArchive(true);
				verify(dstAttrView).setHidden(true);
				verify(dstAttrView).setReadOnly(true);
				verify(dstAttrView).setSystem(true);
			}

			@Test
			@SuppressWarnings("unchecked")
			public void moveDirectoryReplaceExistingNonEmpty() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenReturn(CiphertextFileType.DIRECTORY);
				DirectoryStream<Path> ds = mock(DirectoryStream.class);
				Iterator<Path> iter = mock(Iterator.class);
				when(physicalFsProv.newDirectoryStream(Mockito.same(ciphertextDestinationDir), Mockito.any())).thenReturn(ds);
				when(ds.iterator()).thenReturn(iter);
				when(iter.hasNext()).thenReturn(true);

				Assertions.assertThrows(DirectoryNotEmptyException.class, () -> {
					inTest.copy(cleartextSource, cleartextDestination, StandardCopyOption.REPLACE_EXISTING);
				});
				verify(readonlyFlag).assertWritable();
				verify(ciphertextTargetDirFileChannel, Mockito.never()).write(any(ByteBuffer.class));
				verify(physicalFsProv, Mockito.never()).createDirectory(Mockito.any());
				verify(dirIdProvider, Mockito.never()).delete(Mockito.any());
				verify(cryptoPathMapper, Mockito.never()).invalidatePathMapping(Mockito.any());
			}

			@Test
			public void copyDirectoryToAlreadyExistingDir() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenReturn(CiphertextFileType.DIRECTORY);

				Assertions.assertThrows(FileAlreadyExistsException.class, () -> {
					inTest.copy(cleartextSource, cleartextDestination);
				});
			}

		}

	}

	@Nested
	public class CreateDirectory {

		private final CryptoFileSystemProvider provider = mock(CryptoFileSystemProvider.class);
		private final CryptoFileSystemImpl fileSystem = mock(CryptoFileSystemImpl.class);

		@BeforeEach
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
			Path ciphertextParent = mock(Path.class);
			when(path.getParent()).thenReturn(parent);
			when(cryptoPathMapper.getCiphertextDir(parent)).thenReturn(new CiphertextDirectory("foo", ciphertextParent));
			when(ciphertextParent.getFileSystem()).thenReturn(fileSystem);
			doThrow(NoSuchFileException.class).when(provider).checkAccess(ciphertextParent);

			NoSuchFileException e = Assertions.assertThrows(NoSuchFileException.class, () -> {
				inTest.createDirectory(path);
			});
			Assertions.assertEquals(parent.toString(), e.getFile());
		}

		@Test
		public void createDirectoryIfPathCyphertextFileDoesExistThrowsFileAlreadyException() throws IOException {
			CryptoPath path = mock(CryptoPath.class);
			CryptoPath parent = mock(CryptoPath.class);
			Path ciphertextParent = mock(Path.class);
			when(path.getParent()).thenReturn(parent);
			when(cryptoPathMapper.getCiphertextDir(parent)).thenReturn(new CiphertextDirectory("foo", ciphertextParent));
			when(ciphertextParent.getFileSystem()).thenReturn(fileSystem);
			doThrow(new FileAlreadyExistsException(path.toString())).when(cryptoPathMapper).assertNonExisting(path);

			FileAlreadyExistsException e = Assertions.assertThrows(FileAlreadyExistsException.class, () -> {
				inTest.createDirectory(path);
			});
			Assertions.assertEquals(path.toString(), e.getFile());
		}

		@Test
		public void createDirectoryCreatesDirectoryIfConditonsAreMet() throws IOException {
			CryptoPath path = mock(CryptoPath.class, "path");
			CryptoPath parent = mock(CryptoPath.class, "parent");
			Path ciphertextParent = mock(Path.class, "ciphertextParent");
			Path ciphertextDirFile = mock(Path.class, "ciphertextDirFile");
			Path ciphertextDirPath = mock(Path.class, "ciphertextDir");
			String dirId = "DirId1234ABC";
			FileChannelMock channel = new FileChannelMock(100);
			when(path.getParent()).thenReturn(parent);
			when(cryptoPathMapper.getCiphertextFilePath(path, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextDirFile);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory(dirId, ciphertextDirPath));
			when(cryptoPathMapper.getCiphertextDir(parent)).thenReturn(new CiphertextDirectory("parentDirId", ciphertextDirPath));
			when(cryptoPathMapper.getCiphertextFileType(path)).thenThrow(NoSuchFileException.class);
			when(ciphertextParent.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirFile.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			when(provider.newFileChannel(ciphertextDirFile, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))).thenReturn(channel);

			inTest.createDirectory(path);

			verify(readonlyFlag).assertWritable();
			MatcherAssert.assertThat(channel.data(), is(contains(dirId.getBytes(UTF_8))));
		}

		@Test
		public void createDirectoryClearsDirIdAndDeletesDirFileIfCreatingDirFails() throws IOException {
			CryptoPath path = mock(CryptoPath.class, "path");
			CryptoPath parent = mock(CryptoPath.class, "parent");
			Path ciphertextParent = mock(Path.class, "ciphertextParent");
			Path ciphertextDirFile = mock(Path.class, "ciphertextDirFile");
			Path ciphertextDirPath = mock(Path.class, "ciphertextDir");
			String dirId = "DirId1234ABC";
			FileChannelMock channel = new FileChannelMock(100);
			when(path.getParent()).thenReturn(parent);
			when(cryptoPathMapper.getCiphertextFilePath(path, CiphertextFileType.DIRECTORY)).thenReturn(ciphertextDirFile);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory(dirId, ciphertextDirPath));
			when(cryptoPathMapper.getCiphertextDir(parent)).thenReturn(new CiphertextDirectory("parentDirId", ciphertextDirPath));
			when(cryptoPathMapper.getCiphertextFileType(path)).thenThrow(NoSuchFileException.class);
			when(ciphertextParent.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirFile.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			when(provider.newFileChannel(ciphertextDirFile, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))).thenReturn(channel);

			// make createDirectory with an FileSystemException during Files.createDirectories(ciphertextDirPath)
			doThrow(new IOException()).when(provider).createDirectory(ciphertextDirPath);
			when(ciphertextDirPath.toAbsolutePath()).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getParent()).thenReturn(null);

			Assertions.assertThrows(IOException.class, () -> {
				inTest.createDirectory(path);
			});
			verify(readonlyFlag).assertWritable();
			verify(provider).delete(ciphertextDirFile);
			verify(dirIdProvider).delete(ciphertextDirFile);
			verify(cryptoPathMapper).invalidatePathMapping(path);
		}

	}

	@Nested
	public class IsHidden {

		private final CryptoFileSystemProvider provider = mock(CryptoFileSystemProvider.class);
		private final CryptoFileSystemImpl fileSystem = mock(CryptoFileSystemImpl.class);

		private final CryptoPath path = mock(CryptoPath.class);
		private final Path ciphertextDirPath = mock(Path.class);

		@BeforeEach
		public void setup() throws IOException {
			when(fileSystem.provider()).thenReturn(provider);
			when(cryptoPathMapper.getCiphertextFileType(path)).thenReturn(CiphertextFileType.DIRECTORY);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory("foo", ciphertextDirPath));
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
		}

		@Test
		public void isHiddenReturnsFalseIfDosFileAttributeViewIsNotAvailable() throws IOException {
			MatcherAssert.assertThat(inTest.isHidden(path), is(false));
		}

		@Test
		public void isHiddenReturnsTrueIfDosFileAttributeViewIsAvailableAndIsHiddenIsTrue() throws IOException {
			DosFileAttributeView fileAttributeView = mock(DosFileAttributeView.class);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributeView.readAttributes()).thenReturn(fileAttributes);
			when(fileAttributes.isHidden()).thenReturn(true);
			when(fileAttributeViewProvider.getAttributeView(path, DosFileAttributeView.class)).thenReturn(fileAttributeView);

			MatcherAssert.assertThat(inTest.isHidden(path), is(true));
		}

		@Test
		public void isHiddenReturnsFalseIfDosFileAttributeViewIsAvailableAndIsHiddenIsFalse() throws IOException {
			DosFileAttributeView fileAttributeView = mock(DosFileAttributeView.class);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributeView.readAttributes()).thenReturn(fileAttributes);
			when(fileAttributes.isHidden()).thenReturn(false);
			when(fileAttributeViewProvider.getAttributeView(path, DosFileAttributeView.class)).thenReturn(fileAttributeView);

			MatcherAssert.assertThat(inTest.isHidden(path), is(false));
		}

	}

	@Nested
	public class CheckAccess {

		private final CryptoFileSystemProvider provider = mock(CryptoFileSystemProvider.class);
		private final CryptoFileSystemImpl fileSystem = mock(CryptoFileSystemImpl.class);

		private final CryptoPath path = mock(CryptoPath.class);
		private final Path ciphertextDirPath = mock(Path.class);

		@BeforeEach
		public void setup() throws IOException {
			when(fileSystem.provider()).thenReturn(provider);
			when(cryptoPathMapper.getCiphertextFileType(path)).thenReturn(CiphertextFileType.DIRECTORY);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory("foo", ciphertextDirPath));
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
		}

		@Test
		public void readsBasicAttributesIfNeitherPosixNorDosFileAttributeViewIsSupported() throws IOException {
			inTest.checkAccess(path);
		}

		@Test
		public void throwsExceptionFromReadBasicAttributesIfNeitherPosixNorDosFileAttributeViewIsSupported() throws IOException {
			IOException expectedException = new IOException();
			when(fileAttributeProvider.readAttributes(path, BasicFileAttributes.class)).thenThrow(expectedException);

			IOException e = Assertions.assertThrows(IOException.class, () -> {
				inTest.checkAccess(path);
			});
			Assertions.assertSame(expectedException, e);
		}

		@Test
		public void throwsExceptionFromReadDosAttributesIfDosFileAttributeViewIsSupported() throws IOException {
			IOException expectedException = new IOException();
			when(fileStore.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, DosFileAttributes.class)).thenThrow(expectedException);

			IOException e = Assertions.assertThrows(IOException.class, () -> {
				inTest.checkAccess(path);
			});
			Assertions.assertSame(expectedException, e);
		}

		@Test
		public void succeedsIfDosFileAttributeViewIsSupportedAndFileIsReadOnlyAndWritePermissionIsNotChecked() throws IOException {
			when(fileStore.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributes.isReadOnly()).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, DosFileAttributes.class)).thenReturn(fileAttributes);

			inTest.checkAccess(path);
		}

		@Test
		public void succeedsIfDosFileAttributeViewIsSupportedAndFileIsNotReadOnlyAndWritePermissionIsChecked() throws IOException {
			when(fileStore.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributes.isReadOnly()).thenReturn(false);
			when(fileAttributeProvider.readAttributes(path, DosFileAttributes.class)).thenReturn(fileAttributes);

			inTest.checkAccess(path, AccessMode.WRITE);
		}

		@Test
		public void failsIfDosFileAttributeViewIsSupportedAndFileIsReadOnlyAndWritePermissionIsChecked() throws IOException {
			when(fileStore.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributes.isReadOnly()).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, DosFileAttributes.class)).thenReturn(fileAttributes);

			AccessDeniedException e = Assertions.assertThrows(AccessDeniedException.class, () -> {
				inTest.checkAccess(path, AccessMode.WRITE);
			});
			Assertions.assertEquals(path.toString(), e.getFile());
			Assertions.assertEquals("read only file", e.getReason());
		}

		@Test
		public void throwsExceptionFromReadPosixAttributesIfPosixFileAttributeViewIsSupported() throws IOException {
			IOException expectedException = new IOException();
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, PosixFileAttributes.class)).thenThrow(expectedException);

			IOException e = Assertions.assertThrows(IOException.class, () -> {
				inTest.checkAccess(path);
			});
			Assertions.assertSame(expectedException, e);
		}

		@Test
		public void succeedsIfPosixFileAttributeViewIsSupportedAndNoAccessModeIsChecked() throws IOException {
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, PosixFileAttributes.class)).thenReturn(fileAttributes);

			inTest.checkAccess(path);
		}

		@Test
		public void failsIfPosixFileAttributeViewIsSupportedAndReadAccessModeIsCheckedButNotSupported() throws IOException {
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, PosixFileAttributes.class)).thenReturn(fileAttributes);

			AccessDeniedException e = Assertions.assertThrows(AccessDeniedException.class, () -> {
				inTest.checkAccess(path, AccessMode.READ);
			});
			Assertions.assertEquals(path.toString(), e.getFile());
		}

		@Test
		public void failsIfPosixFileAttributeViewIsSupportedAndWriteAccessModeIsCheckedButNotSupported() throws IOException {
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, PosixFileAttributes.class)).thenReturn(fileAttributes);

			AccessDeniedException e = Assertions.assertThrows(AccessDeniedException.class, () -> {
				inTest.checkAccess(path, AccessMode.WRITE);
			});
			Assertions.assertEquals(path.toString(), e.getFile());
		}

		@Test
		public void failsIfPosixFileAttributeViewIsSupportedAndExecuteAccessModeIsCheckedButNotSupported() throws IOException {
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, PosixFileAttributes.class)).thenReturn(fileAttributes);

			AccessDeniedException e = Assertions.assertThrows(AccessDeniedException.class, () -> {
				inTest.checkAccess(path, AccessMode.EXECUTE);
			});
			Assertions.assertEquals(path.toString(), e.getFile());
		}

		@Test
		public void succeedsIfPosixFileAttributeViewIsSupportedAndReadAccessModeIsCheckedAndSupported() throws IOException {
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, PosixFileAttributes.class)).thenReturn(fileAttributes);
			when(fileAttributes.permissions()).thenReturn(Collections.singleton(PosixFilePermission.OWNER_READ));

			inTest.checkAccess(path, AccessMode.READ);
		}

		@Test
		public void succeedsIfPosixFileAttributeViewIsSupportedAndWriteAccessModeIsCheckedAndSupported() throws IOException {
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, PosixFileAttributes.class)).thenReturn(fileAttributes);
			when(fileAttributes.permissions()).thenReturn(Collections.singleton(PosixFilePermission.OWNER_WRITE));

			inTest.checkAccess(path, AccessMode.WRITE);
		}

		@Test
		public void succeedsIfPosixFileAttributeViewIsSupportedAndExecuteAccessModeIsCheckedAndSupported() throws IOException {
			PosixFileAttributes fileAttributes = mock(PosixFileAttributes.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeProvider.readAttributes(path, PosixFileAttributes.class)).thenReturn(fileAttributes);
			when(fileAttributes.permissions()).thenReturn(Collections.singleton(PosixFilePermission.OWNER_EXECUTE));

			inTest.checkAccess(path, AccessMode.EXECUTE);
		}

		/**
		 * This test ensures, that we get test failures if the {@link AccessMode AccessModes} are extended.
		 * This would allow us to handle the new values in checkAccess accordingly.
		 */
		@Test
		public void testAccessModeContainsOnlyKnownValues() {
			MatcherAssert.assertThat(EnumSet.allOf(AccessMode.class), containsInAnyOrder(AccessMode.READ, AccessMode.WRITE, AccessMode.EXECUTE));
		}

	}

	@Nested
	public class SetAttribute {

		private final CryptoFileSystemProvider provider = mock(CryptoFileSystemProvider.class);
		private final CryptoFileSystemImpl fileSystem = mock(CryptoFileSystemImpl.class);

		@BeforeEach
		public void setup() {
			when(fileSystem.provider()).thenReturn(provider);
		}

		@Test
		public void setAttributeOnRegularDirectory() throws IOException {
			String name = "nameTest123";
			Object value = new Object();
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextFileType(path)).thenReturn(CiphertextFileType.DIRECTORY);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory("foo", ciphertextDirPath));

			inTest.setAttribute(path, name, value);

			verify(readonlyFlag).assertWritable();
			verify(fileAttributeByNameProvider).setAttribute(path, name, value);
		}

		@Test
		public void setAttributeOnNonExistingRootDirectory() throws IOException {
			String name = "nameTest123";
			Object value = new Object();
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextFileType(path)).thenReturn(CiphertextFileType.DIRECTORY);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory("foo", ciphertextDirPath));
			doThrow(new NoSuchFileException("")).when(provider).checkAccess(ciphertextDirPath);

			inTest.setAttribute(path, name, value);

			verify(readonlyFlag).assertWritable();
			verify(fileAttributeByNameProvider).setAttribute(path, name, value);
		}

		@Test
		public void setAttributeOnFile() throws IOException {
			String name = "nameTest123";
			Object value = new Object();
			CryptoPath path = mock(CryptoPath.class);
			Path ciphertextDirPath = mock(Path.class);
			Path ciphertextFilePath = mock(Path.class);
			when(cryptoPathMapper.getCiphertextFileType(path)).thenReturn(CiphertextFileType.FILE);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory("foo", ciphertextDirPath));
			when(cryptoPathMapper.getCiphertextFilePath(path, CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
			doThrow(new NoSuchFileException("")).when(provider).checkAccess(ciphertextDirPath);

			inTest.setAttribute(path, name, value);

			verify(readonlyFlag).assertWritable();
			verify(fileAttributeByNameProvider).setAttribute(path, name, value);
		}

	}

}
