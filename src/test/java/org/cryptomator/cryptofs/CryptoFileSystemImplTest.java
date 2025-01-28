package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.attr.AttributeByNameProvider;
import org.cryptomator.cryptofs.attr.AttributeProvider;
import org.cryptomator.cryptofs.attr.AttributeViewProvider;
import org.cryptomator.cryptofs.attr.AttributeViewType;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.common.FinallyUtil;
import org.cryptomator.cryptofs.common.RunnableThrowingException;
import org.cryptomator.cryptofs.dir.CiphertextDirectoryDeleter;
import org.cryptomator.cryptofs.dir.DirectoryStreamFactory;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles.TwoPhaseMove;
import org.cryptomator.cryptofs.mocks.FileChannelMock;
import org.cryptomator.cryptolib.api.Cryptor;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.ProviderMismatchException;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.spi.FileSystemProvider;
import java.util.Arrays;
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
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
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
	private final DirectoryIdBackup dirIdBackup = mock(DirectoryIdBackup.class);
	private final AttributeProvider fileAttributeProvider = mock(AttributeProvider.class);
	private final AttributeByNameProvider fileAttributeByNameProvider = mock(AttributeByNameProvider.class);
	private final AttributeViewProvider fileAttributeViewProvider = mock(AttributeViewProvider.class);
	private final PathMatcherFactory pathMatcherFactory = mock(PathMatcherFactory.class);
	private final CryptoPathFactory cryptoPathFactory = mock(CryptoPathFactory.class);
	private final CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);
	private final DirectoryStreamFactory directoryStreamFactory = mock(DirectoryStreamFactory.class);
	private final FinallyUtil finallyUtil = mock(FinallyUtil.class);
	private final CiphertextDirectoryDeleter ciphertextDirDeleter = mock(CiphertextDirectoryDeleter.class);
	private final ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);
	private final CryptoFileSystemProperties fileSystemProperties = mock(CryptoFileSystemProperties.class);
	private final FileNameDecryptor filenameDecryptor = mock(FileNameDecryptor.class);

	private final CryptoPath root = mock(CryptoPath.class);
	private final CryptoPath empty = mock(CryptoPath.class);

	private CryptoFileSystemImpl inTest;

	@BeforeEach
	public void setup() {
		when(cryptoPathFactory.rootFor(any())).thenReturn(root);
		when(cryptoPathFactory.emptyFor(any())).thenReturn(empty);
		when(pathToVault.relativize(Mockito.any(Path.class))).then(invocation -> {
			Path other = invocation.getArgument(0);
			return other;
		});

		when(fileSystemProperties.maxCleartextNameLength()).thenReturn(32768);

		inTest = new CryptoFileSystemImpl(provider, cryptoFileSystems, pathToVault, cryptor, //
				fileStore, stats, cryptoPathMapper, cryptoPathFactory, //
				pathMatcherFactory, directoryStreamFactory, dirIdProvider, dirIdBackup, //
				fileAttributeProvider, fileAttributeByNameProvider, fileAttributeViewProvider, //
				openCryptoFiles, symlinks, finallyUtil, ciphertextDirDeleter, readonlyFlag, //
				fileSystemProperties, filenameDecryptor);
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
	public class PathToDataCiphertext {

		@Test
		@DisplayName("Getting data ciphertext path of directory returns ciphertext content dir")
		public void testCleartextDirectory() throws IOException {
			Path ciphertext = Mockito.mock(Path.class, "/d/AB/CD...XYZ/");
			Path cleartext = inTest.getPath("/");
			try (var cryptoPathMock = Mockito.mockStatic(CryptoPath.class)) {
				cryptoPathMock.when(() -> CryptoPath.castAndAssertAbsolute(any())).thenReturn(cleartext);
				when(cryptoPathMapper.getCiphertextFileType(any())).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextDir(any())).thenReturn(new CiphertextDirectory("foo", ciphertext));

				Path result = inTest.getCiphertextPath(cleartext);
				Assertions.assertEquals(ciphertext, result);
				Mockito.verify(cryptoPathMapper, never()).getCiphertextFilePath(any());
			}
		}

		@Test
		@DisplayName("Getting data ciphertext path of file returns ciphertext file")
		public void testCleartextFile() throws IOException {
			Path ciphertext = Mockito.mock(Path.class, "/d/AB/CD..XYZ/foo.c9r");
			Path cleartext = inTest.getPath("/foo.bar");
			try (var cryptoPathMock = Mockito.mockStatic(CryptoPath.class)) {
				CiphertextFilePath p = Mockito.mock(CiphertextFilePath.class);
				cryptoPathMock.when(() -> CryptoPath.castAndAssertAbsolute(any())).thenReturn(cleartext);
				when(cryptoPathMapper.getCiphertextFileType(any())).thenReturn(CiphertextFileType.FILE);
				when(cryptoPathMapper.getCiphertextFilePath(any())).thenReturn(p);
				when(p.getFilePath()).thenReturn(ciphertext);

				Path result = inTest.getCiphertextPath(cleartext);
				Assertions.assertEquals(ciphertext, result);
			}
		}

		@Test
		@DisplayName("Getting data ciphertext path of symlink returns ciphertext symlink.c9r")
		public void testCleartextSymlink() throws IOException {
			Path ciphertext = Mockito.mock(Path.class, "/d/AB/CD..XYZ/foo.c9s/symlink.c9r");
			Path cleartext = inTest.getPath("/foo.bar");
			try (var cryptoPathMock = Mockito.mockStatic(CryptoPath.class)) {
				CiphertextFilePath p = Mockito.mock(CiphertextFilePath.class);
				cryptoPathMock.when(() -> CryptoPath.castAndAssertAbsolute(any())).thenReturn(cleartext);
				when(cryptoPathMapper.getCiphertextFileType(any())).thenReturn(CiphertextFileType.SYMLINK);
				when(cryptoPathMapper.getCiphertextFilePath(any())).thenReturn(p);
				when(p.getSymlinkFilePath()).thenReturn(ciphertext);

				Path result = inTest.getCiphertextPath(cleartext);
				Assertions.assertEquals(ciphertext, result);
			}
		}

		@Test
		@DisplayName("Path not pointing into the vault throws exception")
		public void testForeignPathThrows() throws IOException {
			Path cleartext = Mockito.mock(Path.class, "/some.file");
			Assertions.assertThrows(ProviderMismatchException.class, () -> inTest.getCiphertextPath(cleartext));
		}

		@Test
		@DisplayName("Not existing resource throws NoSuchFileException")
		public void testNoSuchFile() throws IOException {
			Path cleartext = inTest.getPath("/i-do-not-exist");
			try (var cryptoPathMock = Mockito.mockStatic(CryptoPath.class)) {
				cryptoPathMock.when(() -> CryptoPath.castAndAssertAbsolute(any())).thenReturn(cleartext);
				when(cryptoPathMapper.getCiphertextFileType(any())).thenThrow(new NoSuchFileException("no such file"));

				Assertions.assertThrows(NoSuchFileException.class, () -> inTest.getCiphertextPath(cleartext));
			}
		}

		@Test
		@DisplayName("Relative cleartext path throws exception")
		public void testRelativePathException() throws IOException {
			Path cleartext = inTest.getPath("relative/path");
			try (var cryptoPathMock = Mockito.mockStatic(CryptoPath.class)) {
				cryptoPathMock.when(() -> CryptoPath.castAndAssertAbsolute(any())).thenThrow(new IllegalArgumentException());

				Assertions.assertThrows(IllegalArgumentException.class, () -> inTest.getCiphertextPath(cleartext));
			}
		}
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
	public class NewFileChannel {

		private final CryptoPath cleartextPath = mock(CryptoPath.class, "cleartext");
		private final CryptoPath ciphertextFilePath = mock(CryptoPath.class, "d/00/00/path.c9r");
		private final CiphertextFilePath ciphertextPath = mock(CiphertextFilePath.class);
		private final OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class);
		private final FileChannel fileChannel = mock(FileChannel.class);

		@BeforeEach
		public void setup() throws IOException {
			when(cleartextPath.getFileName()).thenReturn(cleartextPath);
			when(cryptoPathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.FILE);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath)).thenReturn(ciphertextPath);
			when(ciphertextPath.getFilePath()).thenReturn(ciphertextFilePath);
			when(openCryptoFiles.getOrCreate(ciphertextFilePath)).thenReturn(openCryptoFile);
			when(ciphertextFilePath.getName(3)).thenReturn(mock(CryptoPath.class, "path.c9r"));
			when(openCryptoFile.newFileChannel(any(), any(FileAttribute[].class))).thenReturn(fileChannel);
		}

		@Nested
		public class LimitedCleartextNameLength {

			@BeforeEach
			public void setup() throws IOException {
				Assumptions.assumeTrue(cleartextPath.getFileName().toString().length() == 9);
			}

			@Test
			@DisplayName("read-only always works")
			public void testNewFileChannelReadOnlyDespiteMaxName() throws IOException {
				Mockito.doReturn(0).when(fileSystemProperties).maxCleartextNameLength();

				FileChannel ch = inTest.newFileChannel(cleartextPath, EnumSet.of(StandardOpenOption.READ));

				Assertions.assertSame(fileChannel, ch);
				verify(readonlyFlag, Mockito.never()).assertWritable();
			}

			@Test
			@DisplayName("create new fails when exceeding limit")
			public void testNewFileChannelCreate1() {
				Mockito.doReturn(0).when(fileSystemProperties).maxCleartextNameLength();

				Assertions.assertThrows(FileNameTooLongException.class, () -> {
					inTest.newFileChannel(cleartextPath, EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE));
				});

				verifyNoInteractions(openCryptoFiles);
			}

			@Test
			@DisplayName("create new succeeds when within limit")
			public void testNewFileChannelCreate2() throws IOException {
				Mockito.doReturn(10).when(fileSystemProperties).maxCleartextNameLength();

				FileChannel ch = inTest.newFileChannel(cleartextPath, EnumSet.of(StandardOpenOption.READ));

				Assertions.assertSame(fileChannel, ch);
				verify(readonlyFlag, Mockito.never()).assertWritable();
			}

			@Test
			@DisplayName("create new and atomically set file attributes")
			public void testNewFileChannelCreate3() throws IOException {
				Mockito.doReturn(10).when(fileSystemProperties).maxCleartextNameLength();
				var attrs = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-x---"));

				FileChannel ch = inTest.newFileChannel(cleartextPath, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attrs);

				Assertions.assertSame(fileChannel, ch);
				verify(openCryptoFile).newFileChannel(Mockito.any(), Mockito.eq(attrs));
			}

		}

		@Test
		@DisplayName("newFileChannel read-only")
		public void testNewFileChannelReadOnly() throws IOException {
			FileChannel ch = inTest.newFileChannel(cleartextPath, EnumSet.of(StandardOpenOption.READ));

			Assertions.assertSame(fileChannel, ch);
			verify(readonlyFlag, Mockito.never()).assertWritable();
		}

		@Test
		@DisplayName("newFileChannel read-write with long filename closed on failed long name persistence")
		public void testNewFileChannelClosedOnErrorAfterCreation() throws IOException {
			Mockito.doThrow(new IOException("ERROR")).when(ciphertextPath).persistLongFileName();

			Assertions.assertThrows(IOException.class, () -> inTest.newFileChannel(cleartextPath, EnumSet.of(StandardOpenOption.WRITE)));
			Mockito.verify(fileChannel).close();
		}

		@Test
		@DisplayName("newFileChannel read-only with long filename")
		public void testNewFileChannelReadOnlyShortened() throws IOException {
			FileChannel ch = inTest.newFileChannel(cleartextPath, EnumSet.of(StandardOpenOption.READ));

			Assertions.assertSame(fileChannel, ch);
			verify(readonlyFlag, Mockito.never()).assertWritable();
			verify(ciphertextPath, Mockito.never()).persistLongFileName();
		}

		@Test
		@DisplayName("newFileChannel read-write with long filename")
		public void testNewFileChannelReadWriteShortened() throws IOException {
			FileChannel ch = inTest.newFileChannel(cleartextPath, EnumSet.of(StandardOpenOption.WRITE));

			Assertions.assertSame(fileChannel, ch);
			verify(readonlyFlag, Mockito.atLeastOnce()).assertWritable();
			verify(ciphertextPath).persistLongFileName();
		}

	}

	@Nested
	public class Delete {

		private final CryptoPath cleartextPath = mock(CryptoPath.class, "cleartext");
		private final Path ciphertextRawPath = mock(Path.class, "d/00/00/path.c9r");
		private final Path ciphertextDirFilePath = mock(Path.class, "d/00/00/path.c9r/dir.c9r");
		private final Path ciphertextFilePath = mock(Path.class, "d/00/00/path.c9r");
		private final Path ciphertextDirPath = mock(Path.class, "d/FF/FF/");
		private final CiphertextFilePath ciphertextPath = mock(CiphertextFilePath.class, "ciphertext");
		private final FileSystem physicalFs = mock(FileSystem.class);
		private final FileSystemProvider physicalFsProv = mock(FileSystemProvider.class);
		private final BasicFileAttributes ciphertextPathAttr = mock(BasicFileAttributes.class);
		private final BasicFileAttributes ciphertextDirFilePathAttr = mock(BasicFileAttributes.class);

		@BeforeEach
		public void setup() throws IOException {
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(ciphertextRawPath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirPath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDirFilePath.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextRawPath.resolve("dir.c9r")).thenReturn(ciphertextDirFilePath);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextPath)).thenReturn(ciphertextPath);
			when(ciphertextPath.getRawPath()).thenReturn(ciphertextRawPath);
			when(ciphertextPath.getFilePath()).thenReturn(ciphertextFilePath);
			when(ciphertextPath.getDirFilePath()).thenReturn(ciphertextDirFilePath);
			when(cryptoPathMapper.getCiphertextDir(cleartextPath)).thenReturn(new CiphertextDirectory("foo", ciphertextDirPath));
			when(physicalFsProv.readAttributes(ciphertextRawPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(ciphertextPathAttr);
			when(physicalFsProv.readAttributes(ciphertextDirFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(ciphertextDirFilePathAttr);

		}

		@Test
		public void testDeleteRootFails() {
			Assertions.assertThrows(FileSystemException.class, () -> inTest.delete(root));
		}

		@Test
		public void testDeleteExistingFile() throws IOException {
			when(cryptoPathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.FILE);
			when(physicalFsProv.deleteIfExists(ciphertextRawPath)).thenReturn(true);
			doNothing().when(openCryptoFiles).delete(Mockito.any());

			inTest.delete(cleartextPath);

			verify(readonlyFlag).assertWritable();
			verify(openCryptoFiles).delete(ciphertextFilePath);
			verify(physicalFsProv).deleteIfExists(ciphertextRawPath);
		}

		@Test
		public void testDeleteExistingDirectory() throws IOException {
			when(cryptoPathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.DIRECTORY);
			when(physicalFsProv.deleteIfExists(ciphertextRawPath)).thenReturn(false);
			when(ciphertextPathAttr.isDirectory()).thenReturn(true);
			when(physicalFsProv.newDirectoryStream(Mockito.eq(ciphertextRawPath), Mockito.any())).thenReturn(new DirectoryStream<Path>() {
				@Override
				public Iterator<Path> iterator() {
					return Arrays.asList(ciphertextDirFilePath).iterator();
				}

				@Override
				public void close() {
					// no-op
				}
			});

			inTest.delete(cleartextPath);
			verify(ciphertextDirDeleter).deleteCiphertextDirIncludingNonCiphertextFiles(ciphertextDirPath, cleartextPath);
			verify(readonlyFlag).assertWritable();
			verify(physicalFsProv).deleteIfExists(ciphertextDirFilePath);
			verify(physicalFsProv).deleteIfExists(ciphertextRawPath);
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
			when(physicalFsProv.deleteIfExists(ciphertextRawPath)).thenReturn(false);
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
		private final CiphertextFilePath ciphertextSource = mock(CiphertextFilePath.class, "ciphertextSource");
		private final CiphertextFilePath ciphertextDestination = mock(CiphertextFilePath.class, "ciphertextDestination");
		private final Path ciphertextSourceFile = mock(Path.class, "d/00/00/source.c9r");
		private final Path ciphertextSourceDirFile = mock(Path.class, "d/00/00/source.c9r/dir.c9r");
		private final Path ciphertextSourceDir = mock(Path.class, "d/00/SOURCE/");
		private final Path ciphertextDestinationFile = mock(Path.class, "d/00/00/dest.c9r");
		private final Path ciphertextDestinationFileName = mock(Path.class, "dest.c9r");
		private final Path ciphertextDestinationLongNameFile = mock(Path.class, "d/00/00/dest.c9r/name.c9s");
		private final Path ciphertextDestinationDirFile = mock(Path.class, "d/00/00/dest.c9r/dir.c9r");
		private final Path ciphertextDestinationDir = mock(Path.class, "d/00/DEST/");
		private final FileSystem physicalFs = mock(FileSystem.class);
		private final FileSystemProvider physicalFsProv = mock(FileSystemProvider.class);

		@BeforeEach
		public void setup() throws IOException {
			when(cleartextDestination.getFileName()).thenReturn(cleartextDestination);
			when(ciphertextSource.getRawPath()).thenReturn(ciphertextSourceFile);
			when(ciphertextSource.getFilePath()).thenReturn(ciphertextSourceFile);
			when(ciphertextSource.getSymlinkFilePath()).thenReturn(ciphertextSourceFile);
			when(ciphertextSource.getDirFilePath()).thenReturn(ciphertextSourceDirFile);
			when(ciphertextDestination.getRawPath()).thenReturn(ciphertextDestinationFile);
			when(ciphertextDestination.getFilePath()).thenReturn(ciphertextDestinationFile);
			when(ciphertextDestination.getSymlinkFilePath()).thenReturn(ciphertextDestinationFile);
			when(ciphertextDestination.getDirFilePath()).thenReturn(ciphertextDestinationDirFile);
			when(ciphertextDestination.getInflatedNamePath()).thenReturn(ciphertextDestinationLongNameFile);
			when(ciphertextSourceFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextSourceDirFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextSourceDir.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDestinationFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDestinationLongNameFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDestinationDirFile.getFileSystem()).thenReturn(physicalFs);
			when(ciphertextDestinationDir.getFileSystem()).thenReturn(physicalFs);
			when(physicalFs.provider()).thenReturn(physicalFsProv);
			when(ciphertextDestinationFile.getName(3)).thenReturn(ciphertextDestinationFileName);
			when(ciphertextDestinationDirFile.getName(3)).thenReturn(ciphertextDestinationFileName);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextSource)).thenReturn(ciphertextSource);
			when(cryptoPathMapper.getCiphertextFilePath(cleartextDestination)).thenReturn(ciphertextDestination);
			when(cryptoPathMapper.getCiphertextDir(cleartextSource)).thenReturn(new CiphertextDirectory("foo", ciphertextSourceDir));
			when(cryptoPathMapper.getCiphertextDir(cleartextDestination)).thenReturn(new CiphertextDirectory("bar", ciphertextDestinationDir));
			when(symlinks.resolveRecursively(cleartextSource)).thenReturn(sourceLinkTarget);
			when(symlinks.resolveRecursively(cleartextDestination)).thenReturn(destinationLinkTarget);
			when(cryptoPathMapper.getCiphertextFileType(sourceLinkTarget)).thenReturn(CiphertextFileType.FILE);
			when(cryptoPathMapper.getCiphertextFileType(destinationLinkTarget)).thenReturn(CiphertextFileType.FILE);
			when(cryptoPathMapper.getCiphertextFilePath(sourceLinkTarget)).thenReturn(ciphertextSource);
			when(cryptoPathMapper.getCiphertextFilePath(destinationLinkTarget)).thenReturn(ciphertextDestination);
		}

		@Nested
		public class Move {

			@Test
			public void moveFileToItselfDoesNothing() throws IOException {
				when(cleartextSource.getFileName()).thenReturn(cleartextSource);

				inTest.move(cleartextSource, cleartextSource);

				verify(readonlyFlag).assertWritable();
				verifyNoInteractions(cryptoPathMapper);
			}

			@Test
			public void moveFilesystemRootFails() {
				Assertions.assertThrows(FileSystemException.class, () -> inTest.move(root, cleartextDestination));
			}

			@Test
			public void moveToFilesystemRootFails() {
				Assertions.assertThrows(FileSystemException.class, () -> inTest.move(cleartextSource, root));
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
				verify(physicalFsProv).move(ciphertextSourceFile, ciphertextDestinationFile, option1, option2);
				verify(dirIdProvider).move(ciphertextSourceDirFile, ciphertextDestinationDirFile);
				verify(cryptoPathMapper).movePathMapping(cleartextSource, cleartextDestination);
			}

			@Test
			@SuppressWarnings("unchecked")
			public void moveDirectoryReplaceExisting() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenReturn(CiphertextFileType.DIRECTORY);
				BasicFileAttributes dirAttr = mock(BasicFileAttributes.class);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextDestinationFile), Mockito.same(BasicFileAttributes.class), Mockito.any())).thenReturn(dirAttr);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextDestinationDir), Mockito.same(BasicFileAttributes.class), Mockito.any())).thenReturn(dirAttr);
				when(dirAttr.isDirectory()).thenReturn(true);
				DirectoryStream<Path> ds = mock(DirectoryStream.class);
				Iterator<Path> iter = mock(Iterator.class);
				when(physicalFsProv.newDirectoryStream(Mockito.same(ciphertextDestinationFile), Mockito.any())).thenReturn(ds);
				when(physicalFsProv.newDirectoryStream(Mockito.same(ciphertextDestinationDir), Mockito.any())).thenReturn(ds);
				when(ds.iterator()).thenReturn(iter);
				when(iter.hasNext()).thenReturn(false);

				inTest.move(cleartextSource, cleartextDestination, StandardCopyOption.REPLACE_EXISTING);

				verify(readonlyFlag).assertWritable();
				verify(physicalFsProv).deleteIfExists(ciphertextDestinationDir);
				verify(physicalFsProv).deleteIfExists(ciphertextDestinationFile);
				verify(physicalFsProv).move(ciphertextSourceFile, ciphertextDestinationFile, StandardCopyOption.REPLACE_EXISTING);
				verify(dirIdProvider).move(ciphertextSourceDirFile, ciphertextDestinationDirFile);
				verify(cryptoPathMapper).movePathMapping(cleartextSource, cleartextDestination);
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
			private final FileChannel ciphertextTargetDirDirFileFileChannel = mock(FileChannel.class);

			@BeforeEach
			public void setup() throws IOException, ReflectiveOperationException {
				when(cleartextDestination.getParent()).thenReturn(cleartextTargetParent);
				when(ciphertextDestinationDir.getParent()).thenReturn(ciphertextTargetDirParent);
				when(ciphertextTargetParent.getFileSystem()).thenReturn(physicalFs);
				when(ciphertextDestinationDir.getFileSystem()).thenReturn(physicalFs);

				when(cryptoPathMapper.getCiphertextDir(cleartextTargetParent)).thenReturn(new CiphertextDirectory("41", ciphertextTargetParent));
				when(cryptoPathMapper.getCiphertextDir(cleartextDestination)).thenReturn(new CiphertextDirectory("42", ciphertextDestinationDir));
				when(physicalFsProv.newFileChannel(Mockito.same(ciphertextDestinationDirFile), Mockito.anySet(), Mockito.any())).thenReturn(ciphertextTargetDirDirFileFileChannel);
			}

			@Test
			public void copyFileToItselfDoesNothing() throws IOException {
				when(cleartextSource.getFileName()).thenReturn(cleartextSource);

				inTest.copy(cleartextSource, cleartextSource);

				verify(readonlyFlag).assertWritable();
				verifyNoInteractions(cryptoPathMapper);
			}

			@Test
			public void copyToRootWithReplacingFails() {
				Assertions.assertThrows(FileSystemException.class, () -> inTest.copy(cleartextSource, root, StandardCopyOption.REPLACE_EXISTING));
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
				when(destinationLinkTarget.getFileName()).thenReturn(destinationLinkTarget);

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
				when(physicalFsProv.newFileChannel(Mockito.eq(ciphertextDestinationDirFile), Mockito.any(), any(FileAttribute[].class))).thenReturn(ciphertextTargetDirDirFileFileChannel);
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				when(physicalFsProv.exists(ciphertextTargetParent)).thenReturn(true);
				Mockito.doThrow(new NoSuchFileException("ciphertextDestinationDirFile")).when(physicalFsProv).checkAccess(ciphertextDestinationFile);

				inTest.copy(cleartextSource, cleartextDestination);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(ciphertextTargetDirDirFileFileChannel).write(any(ByteBuffer.class));
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
				verify(ciphertextTargetDirDirFileFileChannel, Mockito.never()).write(any(ByteBuffer.class));
				verify(physicalFsProv, Mockito.never()).createDirectory(Mockito.any());
				verify(dirIdProvider, Mockito.never()).delete(Mockito.any());
				verify(cryptoPathMapper, Mockito.never()).invalidatePathMapping(Mockito.any());
			}

			@Test
			public void moveDirectoryCopyBasicAttributes() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				Mockito.doThrow(new NoSuchFileException("ciphertextDestinationDirFile")).when(physicalFsProv).checkAccess(ciphertextDestinationFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(EnumSet.of(AttributeViewType.BASIC));
				FileTime lastModifiedTime = FileTime.from(1, TimeUnit.HOURS);
				FileTime lastAccessTime = FileTime.from(2, TimeUnit.HOURS);
				FileTime createTime = FileTime.from(3, TimeUnit.HOURS);
				BasicFileAttributes srcAttrs = mock(BasicFileAttributes.class);
				BasicFileAttributeView dstAttrView = mock(BasicFileAttributeView.class);
				when(srcAttrs.lastModifiedTime()).thenReturn(lastModifiedTime);
				when(srcAttrs.lastAccessTime()).thenReturn(lastAccessTime);
				when(srcAttrs.creationTime()).thenReturn(createTime);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextSourceDir), Mockito.same(BasicFileAttributes.class), any(LinkOption[].class))).thenReturn(srcAttrs);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextDestinationDir), Mockito.same(BasicFileAttributeView.class), any(LinkOption[].class))).thenReturn(dstAttrView);
				when(physicalFsProv.newFileChannel(Mockito.same(ciphertextDestinationDirFile), Mockito.anySet(), any(FileAttribute[].class))).thenReturn(ciphertextTargetDirDirFileFileChannel);
				when(physicalFsProv.exists(ciphertextTargetParent)).thenReturn(true);

				inTest.copy(cleartextSource, cleartextDestination, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setTimes(lastModifiedTime, lastAccessTime, createTime);
			}

			@Test
			public void moveDirectoryCopyFileOwnerAttributes() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				Mockito.doThrow(new NoSuchFileException("ciphertextDestinationDirFile")).when(physicalFsProv).checkAccess(ciphertextDestinationFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(EnumSet.of(AttributeViewType.OWNER));
				UserPrincipal owner = mock(UserPrincipal.class);
				FileOwnerAttributeView srcAttrsView = mock(FileOwnerAttributeView.class);
				FileOwnerAttributeView dstAttrView = mock(FileOwnerAttributeView.class);
				when(srcAttrsView.getOwner()).thenReturn(owner);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextSourceDir), Mockito.same(FileOwnerAttributeView.class), any(LinkOption[].class))).thenReturn(srcAttrsView);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextDestinationDir), Mockito.same(FileOwnerAttributeView.class), any(LinkOption[].class))).thenReturn(dstAttrView);
				when(physicalFsProv.newFileChannel(Mockito.same(ciphertextDestinationDirFile), Mockito.anySet(), any(FileAttribute[].class))).thenReturn(ciphertextTargetDirDirFileFileChannel);
				when(physicalFsProv.exists(ciphertextTargetParent)).thenReturn(true);

				inTest.copy(cleartextSource, cleartextDestination, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setOwner(owner);
			}

			@Test
			@SuppressWarnings("unchecked")
			public void moveDirectoryCopyPosixAttributes() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				Mockito.doThrow(new NoSuchFileException("ciphertextDestinationDirFile")).when(physicalFsProv).checkAccess(ciphertextDestinationFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(EnumSet.of(AttributeViewType.POSIX));
				GroupPrincipal group = mock(GroupPrincipal.class);
				Set<PosixFilePermission> permissions = mock(Set.class);
				PosixFileAttributes srcAttrs = mock(PosixFileAttributes.class);
				PosixFileAttributeView dstAttrView = mock(PosixFileAttributeView.class);
				when(srcAttrs.group()).thenReturn(group);
				when(srcAttrs.permissions()).thenReturn(permissions);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextSourceDir), Mockito.same(PosixFileAttributes.class), any(LinkOption[].class))).thenReturn(srcAttrs);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextDestinationDir), Mockito.same(PosixFileAttributeView.class), any(LinkOption[].class))).thenReturn(dstAttrView);
				when(physicalFsProv.newFileChannel(Mockito.same(ciphertextDestinationDirFile), Mockito.anySet(), any(FileAttribute[].class))).thenReturn(ciphertextTargetDirDirFileFileChannel);
				when(physicalFsProv.exists(ciphertextTargetParent)).thenReturn(true);

				inTest.copy(cleartextSource, cleartextDestination, StandardCopyOption.COPY_ATTRIBUTES);

				verify(readonlyFlag, atLeast(1)).assertWritable();
				verify(dstAttrView).setGroup(group);
				verify(dstAttrView).setPermissions(permissions);
			}

			@Test
			public void moveDirectoryCopyDosAttributes() throws IOException {
				when(cryptoPathMapper.getCiphertextFileType(cleartextSource)).thenReturn(CiphertextFileType.DIRECTORY);
				when(cryptoPathMapper.getCiphertextFileType(cleartextDestination)).thenThrow(NoSuchFileException.class);
				Mockito.doThrow(new NoSuchFileException("ciphertextDestinationDirFile")).when(physicalFsProv).checkAccess(ciphertextDestinationFile);
				when(fileStore.supportedFileAttributeViewTypes()).thenReturn(EnumSet.of(AttributeViewType.DOS));
				DosFileAttributes srcAttrs = mock(DosFileAttributes.class);
				DosFileAttributeView dstAttrView = mock(DosFileAttributeView.class);
				when(srcAttrs.isArchive()).thenReturn(true);
				when(srcAttrs.isHidden()).thenReturn(true);
				when(srcAttrs.isReadOnly()).thenReturn(true);
				when(srcAttrs.isSystem()).thenReturn(true);
				when(physicalFsProv.readAttributes(Mockito.same(ciphertextSourceDir), Mockito.same(DosFileAttributes.class), any(LinkOption[].class))).thenReturn(srcAttrs);
				when(physicalFsProv.getFileAttributeView(Mockito.same(ciphertextDestinationDir), Mockito.same(DosFileAttributeView.class), any(LinkOption[].class))).thenReturn(dstAttrView);
				when(physicalFsProv.newFileChannel(Mockito.same(ciphertextDestinationDirFile), Mockito.anySet(), any(FileAttribute[].class))).thenReturn(ciphertextTargetDirDirFileFileChannel);
				when(physicalFsProv.exists(ciphertextTargetParent)).thenReturn(true);

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
				verify(ciphertextTargetDirDirFileFileChannel, Mockito.never()).write(any(ByteBuffer.class));
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
		private final CryptoPath path = mock(CryptoPath.class, "path");
		private final CryptoPath parent = mock(CryptoPath.class, "parent");

		@BeforeEach
		public void setup() {
			when(fileSystem.provider()).thenReturn(provider);
			when(path.getFileName()).thenReturn(path);
			when(path.getParent()).thenReturn(parent);
		}

		@Test
		public void createFilesystemRootFails() {
			Assertions.assertThrows(FileAlreadyExistsException.class, () -> inTest.createDirectory(root));
		}

		@Test
		public void createDirectoryIfPathHasNoParentDoesNothing() throws IOException {
			when(path.getParent()).thenReturn(null);

			inTest.createDirectory(path);

			verify(readonlyFlag).assertWritable();
			verify(path).getParent();
			verifyNoMoreInteractions(cryptoPathMapper);
		}

		@Test
		public void createDirectoryIfPathsParentDoesNotExistsThrowsNoSuchFileException() throws IOException {
			Path ciphertextParent = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDir(parent)).thenReturn(new CiphertextDirectory("foo", ciphertextParent));
			when(ciphertextParent.getFileSystem()).thenReturn(fileSystem);
			doThrow(NoSuchFileException.class).when(provider).checkAccess(ciphertextParent);

			NoSuchFileException e = Assertions.assertThrows(NoSuchFileException.class, () -> {
				inTest.createDirectory(path);
			});
			Assertions.assertEquals(parent.toString(), e.getFile());
		}

		@Test
		public void createDirectoryIfPathCiphertextFileDoesExistThrowsFileAlreadyException() throws IOException {
			Path ciphertextParent = mock(Path.class);
			when(cryptoPathMapper.getCiphertextDir(parent)).thenReturn(new CiphertextDirectory("foo", ciphertextParent));
			when(ciphertextParent.getFileSystem()).thenReturn(fileSystem);
			doThrow(new FileAlreadyExistsException(path.toString())).when(cryptoPathMapper).assertNonExisting(path);
			when(provider.exists(ciphertextParent)).thenReturn(true);

			FileAlreadyExistsException e = Assertions.assertThrows(FileAlreadyExistsException.class, () -> {
				inTest.createDirectory(path);
			});
			Assertions.assertEquals(path.toString(), e.getFile());
		}

		@Test
		public void createDirectoryCreatesDirectoryIfConditonsAreMet() throws IOException {
			Path ciphertextParent = mock(Path.class, "d/00/00");
			Path ciphertextRawPath = mock(Path.class, "d/00/00/path.c9r");
			Path ciphertextDirFile = mock(Path.class, "d/00/00/path.c9r/dir.c9r");
			Path ciphertextDirPath = mock(Path.class, "d/FF/FF/");
			CiphertextFilePath ciphertextPath = mock(CiphertextFilePath.class, "ciphertext");
			String dirId = "DirId1234ABC";
			FileChannelMock channel = new FileChannelMock(100);
			when(ciphertextRawPath.resolve("dir.c9r")).thenReturn(ciphertextDirFile);
			when(cryptoPathMapper.getCiphertextFilePath(path)).thenReturn(ciphertextPath);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory(dirId, ciphertextDirPath));
			when(cryptoPathMapper.getCiphertextDir(parent)).thenReturn(new CiphertextDirectory("parentDirId", ciphertextParent));
			when(cryptoPathMapper.getCiphertextFileType(path)).thenThrow(NoSuchFileException.class);
			when(ciphertextPath.getRawPath()).thenReturn(ciphertextRawPath);
			when(ciphertextPath.getDirFilePath()).thenReturn(ciphertextDirFile);
			when(ciphertextParent.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextRawPath.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirFile.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirFile.getName(3)).thenReturn(mock(Path.class, "path.c9r"));
			when(provider.newFileChannel(ciphertextDirFile, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))).thenReturn(channel);
			when(provider.exists(ciphertextParent)).thenReturn(true);

			inTest.createDirectory(path);

			verify(readonlyFlag).assertWritable();
			MatcherAssert.assertThat(channel.data(), is(contains(dirId.getBytes(UTF_8))));
		}

		@Test
		public void createDirectoryClearsDirIdAndDeletesDirFileIfCreatingDirFails() throws IOException {
			Path ciphertextParent = mock(Path.class, "d/00/00");
			Path ciphertextRawPath = mock(Path.class, "d/00/00/path.c9r");
			Path ciphertextDirFile = mock(Path.class, "d/00/00/path.c9r/dir.c9r");
			Path ciphertextDirPath = mock(Path.class, "d/FF/FF/");
			CiphertextFilePath ciphertextPath = mock(CiphertextFilePath.class, "ciphertext");
			String dirId = "DirId1234ABC";
			FileChannelMock channel = new FileChannelMock(100);
			when(ciphertextRawPath.resolve("dir.c9r")).thenReturn(ciphertextDirFile);
			when(cryptoPathMapper.getCiphertextFilePath(path)).thenReturn(ciphertextPath);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory(dirId, ciphertextDirPath));
			when(cryptoPathMapper.getCiphertextDir(parent)).thenReturn(new CiphertextDirectory("parentDirId", ciphertextParent));
			when(cryptoPathMapper.getCiphertextFileType(path)).thenThrow(NoSuchFileException.class);
			when(ciphertextPath.getRawPath()).thenReturn(ciphertextRawPath);
			when(ciphertextPath.getDirFilePath()).thenReturn(ciphertextDirFile);
			when(ciphertextParent.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextRawPath.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirFile.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirFile.getName(3)).thenReturn(mock(Path.class, "path.c9r"));
			when(provider.newFileChannel(ciphertextDirFile, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))).thenReturn(channel);
			when(provider.exists(ciphertextParent)).thenReturn(true);

			// make createDirectory with an FileSystemException during Files.createDirectories(ciphertextContentDir)
			doThrow(new IOException()).when(provider).readAttributesIfExists(ciphertextDirPath, BasicFileAttributes.class);
			doThrow(new FileAlreadyExistsException("very specific")).when(provider).createDirectory(ciphertextDirPath);
			when(ciphertextDirPath.toAbsolutePath()).thenReturn(ciphertextDirPath);
			when(ciphertextDirPath.getParent()).thenReturn(null);

			var exception = Assertions.assertThrows(FileAlreadyExistsException.class, () -> {
				inTest.createDirectory(path);
			});
			Assertions.assertEquals("very specific", exception.getMessage());
			verify(readonlyFlag).assertWritable();
			verify(provider).delete(ciphertextDirFile);
			verify(dirIdProvider).delete(ciphertextDirFile);
			verify(cryptoPathMapper).invalidatePathMapping(path);
		}

		@Test
		public void createDirectoryBackupsDirIdInCiphertextDirPath() throws IOException {
			Path ciphertextParent = mock(Path.class, "d/00/00");
			Path ciphertextRawPath = mock(Path.class, "d/00/00/path.c9r");
			Path ciphertextDirFile = mock(Path.class, "d/00/00/path.c9r/dir.c9r");
			Path ciphertextDirPath = mock(Path.class, "d/FF/FF/");
			CiphertextFilePath ciphertextPath = mock(CiphertextFilePath.class, "ciphertext");
			String dirId = "DirId1234ABC";
			CiphertextDirectory ciphertextDirectoryObject = new CiphertextDirectory(dirId, ciphertextDirPath);
			FileChannelMock channel = new FileChannelMock(100);
			when(ciphertextRawPath.resolve("dir.c9r")).thenReturn(ciphertextDirFile);
			when(cryptoPathMapper.getCiphertextFilePath(path)).thenReturn(ciphertextPath);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(ciphertextDirectoryObject);
			when(cryptoPathMapper.getCiphertextDir(parent)).thenReturn(new CiphertextDirectory("parentDirId", ciphertextParent));
			when(cryptoPathMapper.getCiphertextFileType(path)).thenThrow(NoSuchFileException.class);
			when(ciphertextPath.getRawPath()).thenReturn(ciphertextRawPath);
			when(ciphertextPath.getDirFilePath()).thenReturn(ciphertextDirFile);
			when(ciphertextParent.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextRawPath.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirFile.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirPath.getFileSystem()).thenReturn(fileSystem);
			when(ciphertextDirFile.getName(3)).thenReturn(mock(Path.class, "path.c9r"));
			when(provider.newFileChannel(ciphertextDirFile, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))).thenReturn(channel);
			when(provider.exists(ciphertextParent)).thenReturn(true);

			inTest.createDirectory(path);

			verify(readonlyFlag).assertWritable();
			verify(dirIdBackup, Mockito.times(1)).write(ciphertextDirectoryObject);
		}


	}

	@Nested
	public class GetFileAttributeView {

		@Test
		public void getFileAttributeViewReturnsViewIfSupported() {
			CryptoPath path = mock(CryptoPath.class);
			PosixFileAttributeView view = mock(PosixFileAttributeView.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(fileAttributeViewProvider.getAttributeView(path, PosixFileAttributeView.class)).thenReturn(view);

			var result = inTest.getFileAttributeView(path, PosixFileAttributeView.class);

			Assertions.assertSame(view, result);
		}

		@Test
		public void getFileAttributeViewReturnsNullIfViewNotSupported() {
			CryptoPath path = mock(CryptoPath.class);
			when(fileStore.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(false);

			var result = inTest.getFileAttributeView(path, PosixFileAttributeView.class);

			Assertions.assertNull(result);
			Mockito.verifyNoInteractions(fileAttributeViewProvider);
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
			when(fileStore.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
			when(fileAttributeViewProvider.getAttributeView(path, DosFileAttributeView.class)).thenReturn(fileAttributeView);

			MatcherAssert.assertThat(inTest.isHidden(path), is(true));
		}

		@Test
		public void isHiddenReturnsFalseIfDosFileAttributeViewIsAvailableAndIsHiddenIsFalse() throws IOException {
			DosFileAttributeView fileAttributeView = mock(DosFileAttributeView.class);
			DosFileAttributes fileAttributes = mock(DosFileAttributes.class);
			when(fileAttributeView.readAttributes()).thenReturn(fileAttributes);
			when(fileAttributes.isHidden()).thenReturn(false);
			when(fileStore.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
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
			CiphertextFilePath ciphertextPath = mock(CiphertextFilePath.class);
			when(cryptoPathMapper.getCiphertextFileType(path)).thenReturn(CiphertextFileType.FILE);
			when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory("foo", ciphertextDirPath));
			when(cryptoPathMapper.getCiphertextFilePath(path)).thenReturn(ciphertextPath);
			when(ciphertextPath.getFilePath()).thenReturn(ciphertextFilePath);
			doThrow(new NoSuchFileException("")).when(provider).checkAccess(ciphertextDirPath);

			inTest.setAttribute(path, name, value);

			verify(readonlyFlag).assertWritable();
			verify(fileAttributeByNameProvider).setAttribute(path, name, value);
		}

	}

	@Nested
	public class AssertFileNameLength {

		CryptoPath p = Mockito.mock(CryptoPath.class);

		@BeforeEach
		public void init() {
			when(p.getFileName()).thenReturn(p);
			when(p.toString()).thenReturn("takatuka");
		}

		@Test
		public void testFittingPath() {
			when(fileSystemProperties.maxCleartextNameLength()).thenReturn(20);
			Assertions.assertDoesNotThrow(() -> inTest.assertCleartextNameLengthAllowed(p));
		}

		@Test
		public void testTooLongPath() {
			when(fileSystemProperties.maxCleartextNameLength()).thenReturn(4);
			Assertions.assertThrows(FileNameTooLongException.class, () -> inTest.assertCleartextNameLengthAllowed(p));
		}

		@Test
		public void testRootPath() {
			when(fileSystemProperties.maxCleartextNameLength()).thenReturn(0);
			when(p.getFileName()).thenReturn(null);
			Assertions.assertDoesNotThrow(() -> inTest.assertCleartextNameLengthAllowed(p));
		}
	}

}
