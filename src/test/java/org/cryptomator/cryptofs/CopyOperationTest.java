package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.mocks.FileChannelMock;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.EnumSet;

import static java.nio.file.StandardCopyOption.COPY_ATTRIBUTES;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class CopyOperationTest {


	private CopyOperation inTest = new CopyOperation();

	private CryptoFileSystemImpl fileSystemA = mock(CryptoFileSystemImpl.class);
	private CryptoFileSystemImpl fileSystemB = mock(CryptoFileSystemImpl.class);

	private CryptoPath aPathFromFsA = mock(CryptoPath.class);
	private CryptoPath anotherPathFromFsA = mock(CryptoPath.class);

	private CryptoPath aPathFromFsB = mock(CryptoPath.class);
	private CryptoPath anotherPathFromFsB = mock(CryptoPath.class);

	@BeforeEach
	public void setup() {
		when(aPathFromFsA.getFileSystem()).thenReturn(fileSystemA);
		when(anotherPathFromFsA.getFileSystem()).thenReturn(fileSystemA);
		when(aPathFromFsB.getFileSystem()).thenReturn(fileSystemB);
		when(anotherPathFromFsB.getFileSystem()).thenReturn(fileSystemB);
	}

	@Test
	public void testCopyWithEqualPathDoesNothing() throws IOException {
		inTest.copy(aPathFromFsA, aPathFromFsA);

		verifyZeroInteractions(aPathFromFsA);
	}

	@Test
	public void testCopyWithPathFromSameFileSystem() throws IOException {
		inTest.copy(aPathFromFsA, anotherPathFromFsA, StandardCopyOption.ATOMIC_MOVE);

		verify(fileSystemA).copy(aPathFromFsA, anotherPathFromFsA, StandardCopyOption.ATOMIC_MOVE);
	}

	@Test
	public void testCopyExistingFileToNonExistingFileOnDifferentFileSystem() throws IOException {
		FileChannelMock targetFile = new FileChannelMock(100);
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(fileSystemB.readAttributes(aPathFromFsB, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(new NoSuchFileException("aPathFromFsB"));
		when(aPathFromFsAAttributes.isRegularFile()).thenReturn(true);
		when(fileSystemA.newFileChannel(aPathFromFsA, EnumSet.of(READ))).thenReturn(new FileChannelMock(repeat(42).times(20).asByteBuffer()));
		when(fileSystemB.newFileChannel(aPathFromFsB, EnumSet.of(CREATE_NEW, WRITE))).thenReturn(targetFile);

		inTest.copy(aPathFromFsA, aPathFromFsB);

		MatcherAssert.assertThat(targetFile.data(), contains(repeat(42).times(20).asByteBuffer()));
	}

	@Test
	public void testCopyExistingDirectoryToNonExistingDirectoryOnDifferentFileSystem() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(fileSystemB.readAttributes(aPathFromFsB, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(new NoSuchFileException("aPathFromFsB"));
		when(aPathFromFsAAttributes.isDirectory()).thenReturn(true);

		inTest.copy(aPathFromFsA, aPathFromFsB);

		verify(fileSystemB).createDirectory(aPathFromFsB);
	}

	@Test
	public void testCopyNonExistingFileOnDifferentFileSystem() throws IOException {
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenThrow(new NoSuchFileException("aPathFromFsA"));
		when(fileSystemB.readAttributes(aPathFromFsB, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(new NoSuchFileException("aPathFromFsB"));

		NoSuchFileException e = Assertions.assertThrows(NoSuchFileException.class, () -> {
			inTest.copy(aPathFromFsA, aPathFromFsB);
		});
		Assertions.assertEquals(aPathFromFsA.toString(), e.getFile());
	}

	@Test
	public void testCopyExistingFileToExistingFileOnDifferentFileSystemWithReplaceExistingFlag() throws IOException {
		FileChannelMock targetFile = new FileChannelMock(100);
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		BasicFileAttributes aPathFromFsBAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(fileSystemB.readAttributes(aPathFromFsB, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(aPathFromFsBAttributes);
		when(aPathFromFsAAttributes.isRegularFile()).thenReturn(true);
		when(fileSystemA.newFileChannel(aPathFromFsA, EnumSet.of(READ))).thenReturn(new FileChannelMock(repeat(42).times(20).asByteBuffer()));
		when(fileSystemB.newFileChannel(aPathFromFsB, EnumSet.of(CREATE_NEW, WRITE))).thenReturn(targetFile);

		inTest.copy(aPathFromFsA, aPathFromFsB, REPLACE_EXISTING);

		verify(fileSystemB).delete(aPathFromFsB);
		MatcherAssert.assertThat(targetFile.data(), contains(repeat(42).times(20).asByteBuffer()));
	}

	@Test
	public void testCopyExistingFileToExistingFileOnDifferentFileSystemWithoutReplaceExistingFlag() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		BasicFileAttributes aPathFromFsBAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(fileSystemB.readAttributes(aPathFromFsB, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(aPathFromFsBAttributes);

		FileAlreadyExistsException e = Assertions.assertThrows(FileAlreadyExistsException.class, () -> {
			inTest.copy(aPathFromFsA, aPathFromFsB);
		});
		Assertions.assertEquals(aPathFromFsB.toString(), e.getFile());
	}

	@Test
	public void testCopyExistingFileToNonExistingFileOnDifferentFileSystemWithCopyAttributesFlagSetsFileTimes() throws IOException {
		FileTime creationTime = FileTime.fromMillis(3883483);
		FileTime lastModifiedTime = FileTime.fromMillis(3883484);
		FileTime lastAccessTime = FileTime.fromMillis(3883485);
		FileChannelMock targetFile = new FileChannelMock(100);
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		BasicFileAttributeView aPathFromFsBAttributeView = mock(BasicFileAttributeView.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(fileSystemB.getFileAttributeView(aPathFromFsB, BasicFileAttributeView.class)).thenReturn(aPathFromFsBAttributeView);
		when(fileSystemB.readAttributes(aPathFromFsB, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(new NoSuchFileException("aPathFromFsB"));
		when(fileSystemA.newFileChannel(aPathFromFsA, EnumSet.of(READ))).thenReturn(new FileChannelMock(repeat(42).times(20).asByteBuffer()));
		when(fileSystemB.newFileChannel(aPathFromFsB, EnumSet.of(CREATE_NEW, WRITE))).thenReturn(targetFile);
		when(aPathFromFsAAttributes.isRegularFile()).thenReturn(true);
		when(aPathFromFsAAttributes.creationTime()).thenReturn(creationTime);
		when(aPathFromFsAAttributes.lastModifiedTime()).thenReturn(lastModifiedTime);
		when(aPathFromFsAAttributes.lastAccessTime()).thenReturn(lastAccessTime);

		inTest.copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);

		MatcherAssert.assertThat(targetFile.data(), contains(repeat(42).times(20).asByteBuffer()));
		verify(aPathFromFsBAttributeView).setTimes(lastModifiedTime, lastAccessTime, creationTime);
	}

	@Test
	public void testCopyExistingFileToNonExistingFileOnDifferentFileSystemWithCopyAttributesFlagDoesNotSetFileTimesIfNoAttributeViewIsAvailable() throws IOException {
		FileChannelMock targetFile = new FileChannelMock(100);
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(fileSystemB.getFileAttributeView(aPathFromFsB, BasicFileAttributeView.class)).thenReturn(null);
		when(fileSystemB.readAttributes(aPathFromFsB, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(new NoSuchFileException("aPathFromFsB"));
		when(aPathFromFsAAttributes.isRegularFile()).thenReturn(true);
		when(fileSystemA.newFileChannel(aPathFromFsA, EnumSet.of(READ))).thenReturn(new FileChannelMock(repeat(42).times(20).asByteBuffer()));
		when(fileSystemB.newFileChannel(aPathFromFsB, EnumSet.of(CREATE_NEW, WRITE))).thenReturn(targetFile);

		inTest.copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);

		MatcherAssert.assertThat(targetFile.data(), contains(repeat(42).times(20).asByteBuffer()));
	}

	@Test
	public void testCopyExistingSymlinkToNonExistingFileOnDifferentFileSystem() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(aPathFromFsAAttributes);
		when(fileSystemB.readAttributes(aPathFromFsB, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(new NoSuchFileException("aPathFromFsB"));
		when(aPathFromFsAAttributes.isSymbolicLink()).thenReturn(true);
		when(fileSystemA.readSymbolicLink(aPathFromFsA)).thenReturn(anotherPathFromFsA);

		inTest.copy(aPathFromFsA, aPathFromFsB, LinkOption.NOFOLLOW_LINKS);

		verify(fileSystemB).createSymbolicLink(aPathFromFsB, anotherPathFromFsA);
	}

}
