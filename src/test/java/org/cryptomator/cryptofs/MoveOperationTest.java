package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.mocks.DirectoryStreamMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.io.IOException;
import java.net.URI;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.COPY_ATTRIBUTES;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class MoveOperationTest {

	private CopyOperation copyOperation = mock(CopyOperation.class);

	private MoveOperation inTest = new MoveOperation(copyOperation);

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
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);

		inTest.move(aPathFromFsA, aPathFromFsB);

		InOrder inOrder = inOrder(copyOperation, fileSystemA);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verify(fileSystemA).delete(aPathFromFsA);
	}

	@Test
	public void testMovePassesCopyOptionsToCopyAndAddCopyAttributes() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);

		inTest.move(aPathFromFsA, aPathFromFsB, REPLACE_EXISTING);

		InOrder inOrder = inOrder(copyOperation, fileSystemA);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, REPLACE_EXISTING, COPY_ATTRIBUTES);
		inOrder.verify(fileSystemA).delete(aPathFromFsA);
	}

	@Test
	public void testMoveThrowsAtomicMoveNotSupportedExceptionIfInvokedWithAtomicMove() throws IOException {
		URI uriA = URI.create("aPathFromFsAUri");
		URI uriB = URI.create("aPathFromFsBUri");
		when(aPathFromFsA.toUri()).thenReturn(uriA);
		when(aPathFromFsB.toUri()).thenReturn(uriB);

		AtomicMoveNotSupportedException e = Assertions.assertThrows(AtomicMoveNotSupportedException.class, () -> {
			inTest.move(aPathFromFsA, aPathFromFsB, ATOMIC_MOVE);
		});
		Assertions.assertEquals(uriA.toString(), e.getFile());
		Assertions.assertEquals(uriB.toString(), e.getOtherFile());
	}

	@Test
	public void testMoveThrowsIOExceptionIfInvokedWithNonEmptyDirectory() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(aPathFromFsAAttributes.isDirectory()).thenReturn(true);
		when(fileSystemA.newDirectoryStream(same(aPathFromFsA), any())).thenReturn(DirectoryStreamMock.of(mock(Path.class)));

		IOException e = Assertions.assertThrows(IOException.class, () -> {
			inTest.move(aPathFromFsA, aPathFromFsB);
		});
		Assertions.assertEquals("Can not move non empty directory to different FileSystem", e.getMessage());
	}

	@Test
	public void testMoveDoesNotThrowIOExceptionIfFileAttributesOfSourceCanNotBeRead() throws IOException {
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenThrow(IOException.class);

		inTest.move(aPathFromFsA, aPathFromFsB);

		InOrder inOrder = inOrder(copyOperation, fileSystemA);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verify(fileSystemA).delete(aPathFromFsA);
	}

	@Test
	public void testMoveInvokesCopyAndDeleteWhenMovingEmptyDirectory() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		when(aPathFromFsAAttributes.isDirectory()).thenReturn(true);
		when(fileSystemA.newDirectoryStream(same(aPathFromFsA), any())).thenReturn(DirectoryStreamMock.empty());

		inTest.move(aPathFromFsA, aPathFromFsB);
		InOrder inOrder = inOrder(copyOperation, fileSystemA);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verify(fileSystemA).delete(aPathFromFsA);
		inOrder.verifyNoMoreInteractions();
	}

	@Test
	public void testMoveCleansUpTargetIfCopyOperationsFails() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		doThrow(IOException.class).when(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);

		Assertions.assertThrows(IOException.class, () -> {
			inTest.move(aPathFromFsA, aPathFromFsB);
		});

		InOrder inOrder = inOrder(copyOperation, fileSystemB);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verify(fileSystemB).delete(aPathFromFsB);
		inOrder.verifyNoMoreInteractions();
	}

	@Test
	public void testMoveIgnoresExceptionDuringCleanUp() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		IOException expectedException = new IOException();
		doThrow(expectedException).when(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		doThrow(IOException.class).when(fileSystemA).delete(aPathFromFsB);

		IOException e = Assertions.assertThrows(IOException.class, () -> {
			inTest.move(aPathFromFsA, aPathFromFsB);
		});
		Assertions.assertEquals(expectedException, e);
		Assertions.assertEquals(0, e.getSuppressed().length);

		InOrder inOrder = inOrder(copyOperation, fileSystemB);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verify(fileSystemB).delete(aPathFromFsB);
		inOrder.verifyNoMoreInteractions();
	}

	@Test
	public void testMoveDoesNotCleanUpTargetIfCopyOperationsFailsWithFileAlreadyExistsException() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		doThrow(FileAlreadyExistsException.class).when(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);

		inTest.move(aPathFromFsA, aPathFromFsB);

		InOrder inOrder = inOrder(copyOperation, fileSystemA);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verifyNoMoreInteractions();
	}

	@Test
	public void testMoveDoesNotCleanUpTargetIfCopyOperationsFailsWithNoSuchFileException() throws IOException {
		BasicFileAttributes aPathFromFsAAttributes = mock(BasicFileAttributes.class);
		when(fileSystemA.readAttributes(aPathFromFsA, BasicFileAttributes.class)).thenReturn(aPathFromFsAAttributes);
		doThrow(NoSuchFileException.class).when(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);

		inTest.move(aPathFromFsA, aPathFromFsB);

		InOrder inOrder = inOrder(copyOperation, fileSystemA);
		inOrder.verify(copyOperation).copy(aPathFromFsA, aPathFromFsB, COPY_ATTRIBUTES);
		inOrder.verifyNoMoreInteractions();
	}

}
