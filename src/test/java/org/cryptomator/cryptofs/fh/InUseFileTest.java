package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.mockito.Mockito.mock;

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


	@Test
	@DisplayName("Lock files end with .c9l and are in the same directory as the content file")
	public void testGetInUseFilePath(@TempDir Path tmpDir) {
		var currentPath = mock(Path.class, "currentPath");
		var currentFilePath = new AtomicReference<Path>(currentPath);
		Consumer<FilesystemEvent> eventConsumer = e -> {};
		InUseFile inUseFile = new InUseFile(currentFilePath, eventConsumer);

		var path = tmpDir.resolve("hello.abc");
		var result = inUseFile.getInUseFilePath(path);

		Assertions.assertTrue(result.toString().endsWith(".c9l"));
		Assertions.assertEquals(path.getParent(), result.getParent());

	}

	@Test
	@DisplayName("Lock files also work with direct root childs")
	public void testGetInUseFilePathWithRoot(@TempDir Path tmpDir) {
		var currentPath = mock(Path.class, "currentPath");
		var currentFilePath = new AtomicReference<Path>(currentPath);
		Consumer<FilesystemEvent> eventConsumer = e -> {};
		InUseFile inUseFile = new InUseFile(currentFilePath, eventConsumer);
		var rootChild = tmpDir.getRoot().resolve("test3000.abc");

		var result = inUseFile.getInUseFilePath(rootChild);

		Assertions.assertTrue(result.toString().endsWith(".c9l"));
		Assertions.assertEquals(rootChild.getParent(), result.getParent());

	}



}
