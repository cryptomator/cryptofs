package org.cryptomator.cryptofs;

import static java.nio.file.StandardCopyOption.COPY_ATTRIBUTES;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.spi.FileSystemProvider;
import java.util.EnumSet;

import org.cryptomator.cryptofs.mocks.FileChannelMock;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class CopyOperationTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private CopyOperation inTest = new CopyOperation();

	private FileSystemProvider provider = mock(FileSystemProvider.class);

	private CryptoFileSystemImpl fileSystemA = mock(CryptoFileSystemImpl.class);
	private CryptoFileSystemImpl fileSystemB = mock(CryptoFileSystemImpl.class);

	private CryptoPath aPathFromFsA = mock(CryptoPath.class);
	private CryptoPath anotherPathFromFsA = mock(CryptoPath.class);

	private CryptoPath aPathFromFsB = mock(CryptoPath.class);
	private CryptoPath anotherPathFromFsB = mock(CryptoPath.class);

	@Before
	public void setup() {
		when(aPathFromFsA.getFileSystem()).thenReturn(fileSystemA);
		when(anotherPathFromFsA.getFileSystem()).thenReturn(fileSystemA);
		when(aPathFromFsB.getFileSystem()).thenReturn(fileSystemB);
		when(anotherPathFromFsB.getFileSystem()).thenReturn(fileSystemB);

		when(fileSystemA.provider()).thenReturn(provider);
		when(fileSystemB.provider()).thenReturn(provider);
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
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(provider.readAttributes(aPathFromFsB, BasicFileAttributes.class)).thenThrow(new NoSuchFileException("aPathFromFsB"));
		when(provider.newFileChannel(aPathFromFsA, EnumSet.of(READ))).thenReturn(new FileChannelMock(repeat(42).times(20).asByteBuffer()));
		when(provider.newFileChannel(aPathFromFsB, EnumSet.of(CREATE_NEW, WRITE))).thenReturn(targetFile);

		inTest.copy(aPathFromFsA, aPathFromFsB);

		assertThat(targetFile.data(), contains(repeat(42).times(20).asByteBuffer()));
	}

	@Test
	public void testCopyExistingDirectoryToNonExistingDirectoryOnDifferentFileSystem() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(provider.readAttributes(aPathFromFsB, BasicFileAttributes.class)).thenThrow(new NoSuchFileException("aPathFromFsB"));
		when(aPathFromFsAAttributes.isDirectory()).thenReturn(true);

		inTest.copy(aPathFromFsA, aPathFromFsB);

		verify(provider).createDirectory(aPathFromFsB);
	}

	@Test
	public void testCopyNonExistingFileOnDifferentFileSystem() throws IOException {
		URI uri = URI.create("uriOfAPathFromFsA");
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenThrow(new NoSuchFileException("aPathFromFsA"));
		when(provider.readAttributes(aPathFromFsB, BasicFileAttributes.class)).thenThrow(new NoSuchFileException("aPathFromFsB"));
		when(aPathFromFsA.toUri()).thenReturn(uri);

		thrown.expect(NoSuchFileException.class);
		thrown.expectMessage(uri.toString());

		inTest.copy(aPathFromFsA, aPathFromFsB);
	}

	@Test
	public void testCopyExistingFileToExistingFileOnDifferentFileSystemWithReplaceExistingFlag() throws IOException {
		FileChannelMock targetFile = new FileChannelMock(100);
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		BasicFileAttributes aPathFromFsBAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(provider.readAttributes(aPathFromFsB, BasicFileAttributes.class)).thenReturn(aPathFromFsBAttributes);
		when(provider.newFileChannel(aPathFromFsA, EnumSet.of(READ))).thenReturn(new FileChannelMock(repeat(42).times(20).asByteBuffer()));
		when(provider.newFileChannel(aPathFromFsB, EnumSet.of(CREATE_NEW, WRITE))).thenReturn(targetFile);

		inTest.copy(aPathFromFsA, aPathFromFsB, REPLACE_EXISTING);

		verify(provider).delete(aPathFromFsB);
		assertThat(targetFile.data(), contains(repeat(42).times(20).asByteBuffer()));
	}

	@Test
	public void testCopyExistingFileToExistingFileOnDifferentFileSystemWithoutReplaceExistingFlag() throws IOException {
		URI uri = URI.create("uriOfAPathFromFsB");
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		BasicFileAttributes aPathFromFsBAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(provider.readAttributes(aPathFromFsB, BasicFileAttributes.class)).thenReturn(aPathFromFsBAttributes);
		when(aPathFromFsB.toUri()).thenReturn(uri);

		thrown.expect(FileAlreadyExistsException.class);
		thrown.expectMessage(uri.toString());

		inTest.copy(aPathFromFsA, aPathFromFsB);
	}

	@Test
	public void testCopyExistingFileToNonExistingFileOnDifferentFileSystemWithCopyAttributesFlagSetsFileTimes() throws IOException {
		FileTime creationTime = FileTime.fromMillis(3883483);
		FileTime lastModifiedTime = FileTime.fromMillis(3883484);
		FileTime lastAccessTime = FileTime.fromMillis(3883485);
		FileChannelMock targetFile = new FileChannelMock(100);
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		BasicFileAttributeView aPathFromFsBAttributeView = mock(BasicFileAttributeView.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(provider.getFileAttributeView(aPathFromFsB, BasicFileAttributeView.class)).thenReturn(aPathFromFsBAttributeView);
		when(provider.readAttributes(aPathFromFsB, BasicFileAttributes.class)).thenThrow(new NoSuchFileException("aPathFromFsB"));
		when(provider.newFileChannel(aPathFromFsA, EnumSet.of(READ))).thenReturn(new FileChannelMock(repeat(42).times(20).asByteBuffer()));
		when(provider.newFileChannel(aPathFromFsB, EnumSet.of(CREATE_NEW, WRITE))).thenReturn(targetFile);
		when(aPathFromFsAAttributes.creationTime()).thenReturn(creationTime);
		when(aPathFromFsAAttributes.lastModifiedTime()).thenReturn(lastModifiedTime);
		when(aPathFromFsAAttributes.lastAccessTime()).thenReturn(lastAccessTime);

		inTest.copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);

		assertThat(targetFile.data(), contains(repeat(42).times(20).asByteBuffer()));
		verify(aPathFromFsBAttributeView).setTimes(lastModifiedTime, lastAccessTime, creationTime);
	}

	@Test
	public void testCopyExistingFileToNonExistingFileOnDifferentFileSystemWithCopyAttributesFlagDoesNotSetFileTimesIfNoAttributeViewIsAvailable() throws IOException {
		FileChannelMock targetFile = new FileChannelMock(100);
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(provider.getFileAttributeView(aPathFromFsB, BasicFileAttributeView.class)).thenReturn(null);
		when(provider.readAttributes(aPathFromFsB, BasicFileAttributes.class)).thenThrow(new NoSuchFileException("aPathFromFsB"));
		when(provider.newFileChannel(aPathFromFsA, EnumSet.of(READ))).thenReturn(new FileChannelMock(repeat(42).times(20).asByteBuffer()));
		when(provider.newFileChannel(aPathFromFsB, EnumSet.of(CREATE_NEW, WRITE))).thenReturn(targetFile);

		inTest.copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);

		assertThat(targetFile.data(), contains(repeat(42).times(20).asByteBuffer()));
	}

}
