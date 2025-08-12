package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.common.Constants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;


/*
	To test:
	* acquire
	* readInUseFile
	* createInUseFile
	* writeInUseFile
	* ownInUseFile
	* close
	* getInUseFilePath
 */
public class InUseFileTest {

	Path ciphertextPath = mock(Path.class, "ciphertextPath");
	AtomicReference<Path> currentFilePath = new AtomicReference<>();
	SeekableByteChannel inUseChannel = mock(SeekableByteChannel.class);
	Properties info = new Properties();
	InUseFile inUseFile;

	@BeforeEach
	public void beforeEach() {
		currentFilePath.set(ciphertextPath);
		inUseFile = new InUseFile(currentFilePath, "cryptobot", inUseChannel, info);
	}

	@Test
	@DisplayName("Acquiring existing, valid inUseFile")
	public void testAcquireExistingSameOwner() throws IOException {
		var inUseFileSpy = spy(inUseFile);

		Path inUsePath = mock(Path.class, "inUseFilePath");
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.isInUse(eq(inUsePath), any())).thenReturn(false);
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);

			var isInUse = inUseFileSpy.acquire();

			Assertions.assertTrue(isInUse);
			verify(inUseFileSpy, never()).createInUseFile(inUsePath);
			verify(inUseFileSpy, never()).stealInUseFile(inUsePath);
			//TODO: check, that inUse file is updated
		}
	}

	@Test
	@DisplayName("Acquiring existing, valid inUseFile with different owner throws exception")
	public void testAcquireExistingDifferentOwnerThrows() throws IOException {
		var inUseFileSpy = spy(inUseFile);

		Path inUsePath = mock(Path.class, "inUseFilePath");
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.isInUse(eq(inUsePath), any())).thenReturn(true);
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);

			Executable test = () -> inUseFile.acquire();

			Assertions.assertThrows(FileAlreadyInUseException.class, test);

			verify(inUseFileSpy, never()).createInUseFile(inUsePath);
			verify(inUseFileSpy, never()).stealInUseFile(inUsePath);
		}
	}

	@Test
	@DisplayName("Acquire existing, invalid inUseFile steals it")
	public void testAcquireReadExistingInvalid() throws IOException {
		var inUseFileSpy = spy(inUseFile);
		Path inUsePath = mock(Path.class, "inUseFilePath");
		doReturn(true).when(inUseFileSpy).stealInUseFile(inUsePath);
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.isInUse(eq(inUsePath), any())).thenThrow(IllegalArgumentException.class);
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);

			var isAcquired = inUseFileSpy.acquire();

			Assertions.assertTrue(isAcquired);
			verify(inUseFileSpy).stealInUseFile(inUsePath);
			verify(inUseFileSpy, never()).createInUseFile(inUsePath);
		}
	}

	@Test
	@DisplayName("Acquire existing, invalid inUseFile with failing steal")
	public void testAcquireReadExistingInvalidFailedSteal() throws IOException {
		var inUseFileSpy = spy(inUseFile);
		Path inUsePath = mock(Path.class, "inUseFilePath");
		doReturn(false).when(inUseFileSpy).stealInUseFile(inUsePath);
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.isInUse(eq(inUsePath), any())).thenThrow(IllegalArgumentException.class);
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);
			when(inUseFileSpy.stealInUseFile(inUsePath)).thenReturn(false);

			var isAcquired = inUseFileSpy.acquire();

			Assertions.assertFalse(isAcquired);
			verify(inUseFileSpy).stealInUseFile(inUsePath);
			verify(inUseFileSpy, never()).createInUseFile(inUsePath);
		}
	}

	@Test
	@DisplayName("Acquire not existing inUseFile creates it")
	public void testAcquireCreateNew() throws IOException {
		var inUseFileSpy = spy(inUseFile);
		Path inUsePath = mock(Path.class, "inUseFilePath");
		doReturn(true).when(inUseFileSpy).createInUseFile(inUsePath);
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.isInUse(eq(inUsePath), any())).thenThrow(NoSuchFileException.class);
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);

			var isAcquired = inUseFileSpy.acquire();

			Assertions.assertTrue(isAcquired);
			verify(inUseFileSpy).createInUseFile(inUsePath);
			verify(inUseFileSpy, never()).stealInUseFile(inUsePath);
		}
	}

	@Test
	@DisplayName("Acquire not existing inUseFile with failing create")
	public void testAcquireCreateNewFailing() throws IOException {
		var inUseFileSpy = spy(inUseFile);
		Path inUsePath = mock(Path.class, "inUseFilePath");
		doReturn(false).when(inUseFileSpy).createInUseFile(inUsePath);
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.isInUse(eq(inUsePath), any())).thenThrow(NoSuchFileException.class);
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);
			when(inUseFileSpy.createInUseFile(inUsePath)).thenReturn(false);

			var isAcquired = inUseFileSpy.acquire();

			Assertions.assertFalse(isAcquired);
			verify(inUseFileSpy).createInUseFile(inUsePath);
			verify(inUseFileSpy, never()).stealInUseFile(inUsePath);
		}
	}


	@Test
	@DisplayName("Lock files end with .c9u and are in the same directory as the content file")
	public void testComputeInUseFilePath(@TempDir Path tmpDir) {
		var path = tmpDir.resolve("hello.abc");
		var result = InUseFile.computeInUseFilePath(path);

		Assertions.assertTrue(result.toString().endsWith(Constants.INUSE_FILE_SUFFIX));
		Assertions.assertEquals(path.getParent(), result.getParent());

	}

	@Test
	@DisplayName("Lock files also work with direct root childs")
	public void testComputeInUseFilePathWithRoot(@TempDir Path tmpDir) {
		var rootChild = tmpDir.getRoot().resolve("test3000.abc");

		var result = InUseFile.computeInUseFilePath(rootChild);

		Assertions.assertTrue(result.toString().endsWith(Constants.INUSE_FILE_SUFFIX));
		Assertions.assertEquals(rootChild.getParent(), result.getParent());
	}

	@Test
	@DisplayName("Close closes inUseFileChannel and removes inUse file")
	public void testClose() throws IOException {
		var inUseFileSpy = spy(inUseFile);
		Path inUsePath = mock(Path.class, "inUseFilePath");
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);
			doNothing().when(inUseFileSpy).deleteInUseFile(any());

			inUseFileSpy.close();

			verify(inUseChannel).close();
			verify(inUseFileSpy).deleteInUseFile(inUsePath);
		}
	}

	@Test
	@DisplayName("Close does not propagate IO exception")
	public void testCloseFailing() throws IOException {
		var inUseFileSpy = spy(inUseFile);
		Path inUsePath = mock(Path.class, "inUseFilePath");
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);

			doThrow(IOException.class).when(inUseFileSpy).deleteInUseFile(any());
			Assertions.assertDoesNotThrow(inUseFileSpy::close);

			doThrow(IOException.class).when(inUseChannel).close();
			Assertions.assertDoesNotThrow(inUseFileSpy::close);
		}
	}

	@Test
	@DisplayName("Closing after first close() does nothing")
	public void testClosedForGood() throws IOException {
		var inUseFileSpy = spy(inUseFile);
		Path inUsePath = mock(Path.class, "inUseFilePath");
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);
			doNothing().when(inUseFileSpy).deleteInUseFile(any());
			doNothing().when(inUseChannel).close();

			Assertions.assertDoesNotThrow(inUseFileSpy::close);
			verify(inUseChannel, times(1)).close();
			verify(inUseFileSpy, times(1)).deleteInUseFile(inUsePath);

			Assertions.assertDoesNotThrow(inUseFileSpy::close);
			verifyNoMoreInteractions(inUseChannel);
			verify(inUseFileSpy, times(1)).deleteInUseFile(inUsePath);
		}
	}

	@Test
	@DisplayName("Closing with failure still marks the file as closed")
	public void testClosedForGoodWithFailure() throws IOException {
		var inUseFileSpy = spy(inUseFile);
		Path inUsePath = mock(Path.class, "inUseFilePath");
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);
			doThrow(IOException.class).when(inUseFileSpy).deleteInUseFile(any());
			doThrow(IOException.class).when(inUseChannel).close();

			Assertions.assertDoesNotThrow(inUseFileSpy::close);
			verify(inUseChannel, times(1)).close();
			verify(inUseFileSpy, times(1)).deleteInUseFile(inUsePath);

			Assertions.assertDoesNotThrow(inUseFileSpy::close);
			verifyNoMoreInteractions(inUseChannel);
			verify(inUseFileSpy, times(1)).deleteInUseFile(inUsePath);
		}
	}

	@Test
	@DisplayName("Closing with null as currentFilePath skips deletion")
	public void testCloseWithNullFilePath() throws IOException {
		currentFilePath.set(null);
		var inUseFileSpy = spy(inUseFile);
		try (var classMock = mockStatic(InUseFile.class)) {
			doNothing().when(inUseChannel).close();

			Assertions.assertDoesNotThrow(inUseFileSpy::close);

			verify(inUseFileSpy, never()).deleteInUseFile(any());
			classMock.verify(() -> InUseFile.computeInUseFilePath(any()), never());
		}
	}
}
