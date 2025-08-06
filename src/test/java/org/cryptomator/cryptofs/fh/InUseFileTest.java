package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.event.FileIsInUseEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentMatcher;
import org.mockito.ArgumentMatchers;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class InUseFileTest {

	/*
		To test:
		* checkOrOwn
		* readInUseFile
		* createInUseFile
		* writeInUseFile
		* ownInUseFile
		* close
		* getInUseFilePath
	 */

	AtomicReference<Path> currentFilePath = new AtomicReference<>();
	Consumer<FilesystemEvent> eventConsumer = mock(Consumer.class);
	SeekableByteChannel inUseChannel = mock(SeekableByteChannel.class);
	Properties info = new Properties();
	InUseFile inUseFile;

	@BeforeEach
	public void beforeEach() {
		inUseFile = new InUseFile(currentFilePath, eventConsumer, "cryptobot", inUseChannel, info);
	}

	@Test
	@DisplayName("CheckOrOwn for existing, valid inUseFile with same owner")
	public void testTryMarkInUseReadExistingSameOwner() throws IOException {
		var inUseFileSpy = spy(inUseFile);

		var inUseInfo = new Properties();
		inUseInfo.put("owner", "cryptobot");
		Path inUsePath = mock(Path.class, "inUseFilePath");
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.readInUseFile(inUsePath)).thenReturn(inUseInfo);
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);

			var isInUse = inUseFileSpy.tryMarkInUse();

			Assertions.assertFalse(isInUse);
			verify(inUseFileSpy, never()).createInUseFile(inUsePath);
			verify(inUseFileSpy, never()).ownInUseFile(inUsePath);
			//TODO: check, that inUse file is updated
		}
	}

	@Test
	@DisplayName("CheckOrOwn for existing, valid inUseFile with different owner")
	public void testTryMarkInUseReadExistingDifferentOwner() throws IOException {
		var inUseFileSpy = spy(inUseFile);

		var inUseInfo = new Properties();
		inUseInfo.put("owner", "cryptobot3000");
		Path inUsePath = mock(Path.class, "inUseFilePath");
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.readInUseFile(inUsePath)).thenReturn(inUseInfo);
			classMock.when(() -> InUseFile.isInUse(eq(inUsePath), any())).thenCallRealMethod();
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);

			var isInUse = inUseFileSpy.tryMarkInUse();

			Assertions.assertTrue(isInUse);
			verify(inUseFileSpy, never()).createInUseFile(inUsePath);
			verify(inUseFileSpy, never()).ownInUseFile(inUsePath);
			var isFileIsInUseEvent = (ArgumentMatcher<FilesystemEvent>) ev -> ev instanceof FileIsInUseEvent;
			verify(eventConsumer).accept(ArgumentMatchers.argThat(isFileIsInUseEvent));
		}
	}

	@Test
	@DisplayName("CheckOrOwn for existing, invalid inUseFile owns it")
	public void testTryMarkInUseReadExistingInvalid() throws IOException {
		var inUseFileSpy = spy(inUseFile);
		Path inUsePath = mock(Path.class, "inUseFilePath");
		doNothing().when(inUseFileSpy).ownInUseFile(inUsePath);
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.isInUse(eq(inUsePath), any())).thenCallRealMethod();
			classMock.when(() -> InUseFile.readInUseFile(inUsePath)).thenThrow(IllegalArgumentException.class);
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);

			var isInUse = inUseFileSpy.tryMarkInUse();

			Assertions.assertFalse(isInUse);
			verify(inUseFileSpy).ownInUseFile(inUsePath);
			verify(inUseFileSpy, never()).createInUseFile(inUsePath);
		}
	}

	@Test
	@DisplayName("CheckOrOwn creates inUseFile if it does not exist")
	public void testTryMarkInUseCreateNew() throws IOException {
		var inUseFileSpy = spy(inUseFile);
		Path inUsePath = mock(Path.class, "inUseFilePath");
		doNothing().when(inUseFileSpy).createInUseFile(inUsePath);
		try (var classMock = mockStatic(InUseFile.class)) {
			classMock.when(() -> InUseFile.isInUse(eq(inUsePath), any())).thenCallRealMethod();
			classMock.when(() -> InUseFile.readInUseFile(inUsePath)).thenThrow(NoSuchFileException.class);
			classMock.when(() -> InUseFile.computeInUseFilePath(any())).thenReturn(inUsePath);

			var isInUse = inUseFileSpy.tryMarkInUse();

			Assertions.assertFalse(isInUse);
			verify(inUseFileSpy).createInUseFile(inUsePath);
			verify(inUseFileSpy, never()).ownInUseFile(inUsePath);
		}
	}


	@Test
	@DisplayName("Lock files end with .c9l and are in the same directory as the content file")
	public void testComputeInUseFilePath(@TempDir Path tmpDir) {
		var path = tmpDir.resolve("hello.abc");
		var result = InUseFile.computeInUseFilePath(path);

		Assertions.assertTrue(result.toString().endsWith(".c9l"));
		Assertions.assertEquals(path.getParent(), result.getParent());

	}

	@Test
	@DisplayName("Lock files also work with direct root childs")
	public void testComputeInUseFilePathWithRoot(@TempDir Path tmpDir) {
		var rootChild = tmpDir.getRoot().resolve("test3000.abc");

		var result = InUseFile.computeInUseFilePath(rootChild);

		Assertions.assertTrue(result.toString().endsWith(".c9l"));
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


}
