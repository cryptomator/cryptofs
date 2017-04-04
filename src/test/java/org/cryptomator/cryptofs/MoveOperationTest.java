package org.cryptomator.cryptofs;

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.COPY_ATTRIBUTES;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;

import org.cryptomator.cryptofs.mocks.DirectoryStreamMock;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.InOrder;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class MoveOperationTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private CopyOperation copyOperation = mock(CopyOperation.class);

	private MoveOperation inTest = new MoveOperation(copyOperation);

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
	public void testMoveWithEqualPathDoesNothing() throws IOException {
		inTest.move(aPathFromFsA, aPathFromFsA);

		verifyZeroInteractions(aPathFromFsA);
	}

	@Test
	public void testCopyWithPathFromSameFileSystem() throws IOException {
		inTest.move(aPathFromFsA, anotherPathFromFsA, StandardCopyOption.ATOMIC_MOVE);

		verify(fileSystemA).move(aPathFromFsA, anotherPathFromFsA, StandardCopyOption.ATOMIC_MOVE);
	}

	@Test
	public void testMoveInvokesCopyAndDeleteOnFilesFromDifferentFileSystem() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);

		inTest.move(aPathFromFsA, aPathFromFsB);

		InOrder inOrder = inOrder(copyOperation, provider);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verify(provider).deleteIfExists(aPathFromFsA);
	}

	@Test
	public void testMovePassesCopyOptionsToCopyAndAddCopyAttributes() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);

		inTest.move(aPathFromFsA, aPathFromFsB, REPLACE_EXISTING);

		InOrder inOrder = inOrder(copyOperation, provider);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, REPLACE_EXISTING, COPY_ATTRIBUTES);
		inOrder.verify(provider).deleteIfExists(aPathFromFsA);
	}

	@Test
	public void testMoveThrowsAtomicMoveNotSupportedExceptionIfInvokedWithAtomicMove() throws IOException {
		URI uriA = URI.create("aPathFromFsAUri");
		URI uriB = URI.create("aPathFromFsBUri");
		when(aPathFromFsA.toUri()).thenReturn(uriA);
		when(aPathFromFsB.toUri()).thenReturn(uriB);

		thrown.expect(AtomicMoveNotSupportedException.class);
		thrown.expectMessage(uriA.toString());
		thrown.expectMessage(uriB.toString());

		inTest.move(aPathFromFsA, aPathFromFsB, ATOMIC_MOVE);
	}

	@Test
	public void testMoveThrowsIOExceptionIfInvokedWithNonEmptyDirectory() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(aPathFromFsAAttributes.isDirectory()).thenReturn(true);
		when(provider.newDirectoryStream(same(aPathFromFsA), any())).thenReturn(DirectoryStreamMock.of(mock(Path.class)));

		thrown.expect(IOException.class);
		thrown.expectMessage("Can not move non empty directory to different FileSystem");

		inTest.move(aPathFromFsA, aPathFromFsB);
	}

	@Test
	public void testMoveDoesNotThrowIOExceptionIfFileAttributesOfSourceCanNotBeRead() throws IOException {
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenThrow(IOException.class);

		inTest.move(aPathFromFsA, aPathFromFsB);

		InOrder inOrder = inOrder(copyOperation, provider);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verify(provider).deleteIfExists(aPathFromFsA);
	}

	@Test
	public void testMoveInvokesCopyAndDeleteWhenMovingEmptyDirectory() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(aPathFromFsAAttributes.isDirectory()).thenReturn(true);
		when(provider.newDirectoryStream(same(aPathFromFsA), any())).thenReturn(DirectoryStreamMock.empty());

		inTest.move(aPathFromFsA, aPathFromFsB);
		InOrder inOrder = inOrder(copyOperation, provider);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verify(provider).deleteIfExists(aPathFromFsA);
		inOrder.verifyNoMoreInteractions();
	}

	@Test
	public void testMoveCleansUpTargetIfCopyOperationsFails() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		doThrow(IOException.class).when(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);

		try {
			inTest.move(aPathFromFsA, aPathFromFsB);
		} catch (IOException e) {

		}

		InOrder inOrder = inOrder(copyOperation, provider);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verify(provider).deleteIfExists(aPathFromFsB);
		inOrder.verifyNoMoreInteractions();
	}

	@Test
	public void testMoveIgnoresExceptionDuringCleanUp() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		IOException expectedException = new IOException();
		doThrow(expectedException).when(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		doThrow(IOException.class).when(provider).deleteIfExists(aPathFromFsB);

		try {
			inTest.move(aPathFromFsA, aPathFromFsB);
		} catch (IOException e) {
			assertThat(e, is(expectedException));
			assertThat(e.getSuppressed().length, is(0));
		}

		InOrder inOrder = inOrder(copyOperation, provider);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verify(provider).deleteIfExists(aPathFromFsB);
		inOrder.verifyNoMoreInteractions();
	}

	@Test
	public void testMoveDoesNotCleanUpTargetIfCopyOperationsFailsWithFileAlreadyExistsException() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		doThrow(FileAlreadyExistsException.class).when(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);

		try {
			inTest.move(aPathFromFsA, aPathFromFsB);
		} catch (IOException e) {

		}

		InOrder inOrder = inOrder(copyOperation, provider);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verifyNoMoreInteractions();
	}

	@Test
	public void testMoveDoesNotCleanUpTargetIfCopyOperationsFailsWithNoSuchFileException() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(provider.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		doThrow(NoSuchFileException.class).when(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);

		try {
			inTest.move(aPathFromFsA, aPathFromFsB);
		} catch (IOException e) {

		}

		InOrder inOrder = inOrder(copyOperation, provider);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verifyNoMoreInteractions();
	}

}
