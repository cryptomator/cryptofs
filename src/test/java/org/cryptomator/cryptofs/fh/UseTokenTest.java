package org.cryptomator.cryptofs.fh;

import org.awaitility.Awaitility;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchService;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public class UseTokenTest {

	private ConcurrentMap<Path, UseToken> useTokens;
	@TempDir
	Path tmpDir;
	private WatchService watchService;

	@BeforeEach
	public void beforeEach() throws IOException {
		useTokens = new ConcurrentHashMap<>();//Mockito.mock(ConcurrentMap.class);
		watchService = tmpDir.getFileSystem().newWatchService();
	}

	@AfterEach
	public void afterEach() {
		try {
			watchService.close();
		} catch (IOException e) {
			//no-op
		}
	}

	@Test
	@DisplayName("After 5 seconds of token creation, a new file is created")
	public void testFileCreation() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		try (var token = UseToken.createWithNewFile(filePath, useTokens)) {
			Awaitility.await().atLeast(5, TimeUnit.SECONDS).atMost(8, TimeUnit.SECONDS).until(() -> Files.exists(filePath));
			Assertions.assertTrue(Files.exists(filePath));
		}
		Assertions.assertTrue(Files.notExists(filePath));
	}

	@Test
	@DisplayName("After 5 seconds of token creation, a file is updated")
	public void testFileSteal() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		Files.createFile(filePath);
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
		var fileTime = Files.getLastModifiedTime(filePath);

		try (var token = UseToken.createWithExistingInvalidFile(filePath, useTokens)) {
			Awaitility.await().atLeast(5, TimeUnit.SECONDS).atMost(8, TimeUnit.SECONDS).until(() -> fileTime.compareTo(Files.getLastModifiedTime(filePath)) < 0);
			var events = watchKey.pollEvents();
			var createEvent = events.stream().filter(e -> e.kind().equals(StandardWatchEventKinds.ENTRY_MODIFY)).findAny();
			Assertions.assertTrue(createEvent.isPresent());
			createEvent.ifPresent(e -> {
				Assertions.assertEquals(1, e.count());
				Assertions.assertTrue(filePath.endsWith((Path) e.context()));
			});
		}
		Assertions.assertTrue(Files.notExists(filePath));
		Assertions.assertNull(useTokens.get(filePath));
	}

	@Test
	@DisplayName("After 5 seconds of token creation, failed steal closes the token ")
	public void testFileStealFails() throws IOException {
		var filePath = tmpDir.resolve("inUse.file"); //file does not exist
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = UseToken.createWithExistingInvalidFile(filePath, useTokens)) {
			Awaitility.await().atLeast(4950, TimeUnit.MILLISECONDS).atMost(10, TimeUnit.SECONDS).until(token::isClosed);
			Assertions.assertTrue(Files.notExists(filePath));
			Assertions.assertTrue(token.isClosed());
			Assertions.assertNull(useTokens.get(filePath));
		}
		MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
	}

	@Test
	@DisplayName("Closing a UseToken before 5 seconds passed skips file creation")
	public void testTokenCloseBeforeFileOperation() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = UseToken.createWithNewFile(filePath, useTokens)) {
			Assertions.assertTrue(Files.notExists(filePath));
		}
		Awaitility.await().pollDelay(7, TimeUnit.SECONDS).timeout(10, TimeUnit.SECONDS).until(() -> true);
		Assertions.assertTrue(Files.notExists(filePath));
		Assertions.assertNull(useTokens.get(filePath));
		MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
	}

	@Test
	@DisplayName("Moving a token before file creation")
	public void testMoveBefore() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var targetPath = tmpDir.resolve("inUse2.file");
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = UseToken.createWithNewFile(filePath, useTokens)) {
			token.move(targetPath);

			//no file operation after move
			MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
			// target file will be created
			Awaitility.await().atLeast(5000, TimeUnit.MILLISECONDS).atMost(10, TimeUnit.SECONDS).until(() -> Files.exists(targetPath));
			//orginal filePath does not exist, target exists
			Assertions.assertTrue(Files.notExists(filePath));
			Assertions.assertTrue(Files.exists(targetPath));

			//only targetPath was created
			var events = watchKey.pollEvents();
			var createEvent = events.stream().filter(e -> e.kind().equals(StandardWatchEventKinds.ENTRY_CREATE)).findAny();
			Assertions.assertTrue(createEvent.isPresent());
			createEvent.ifPresent(e -> {
				Assertions.assertEquals(1, e.count());
				Assertions.assertTrue(targetPath.endsWith((Path) e.context()));
			});
		}
		Assertions.assertNull(useTokens.get(filePath));
		Assertions.assertNull(useTokens.get(targetPath));
	}

	@Test
	@DisplayName("Moving a token after file creation")
	public void testMoveAfter() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var targetPath = tmpDir.resolve("inUse2.file");

		try (var token = UseToken.createWithNewFile(filePath, useTokens)) {
			Awaitility.await().atLeast(4950, TimeUnit.MILLISECONDS).atMost(10, TimeUnit.SECONDS).until(() -> Files.exists(filePath));

			token.move(targetPath);

			// target file will be created
			// orginal filePath does not exist, target exists
			Assertions.assertTrue(Files.notExists(filePath));
			Assertions.assertTrue(Files.exists(targetPath));
			Assertions.assertNull(useTokens.get(filePath));
			Assertions.assertNotNull(useTokens.get(targetPath));
		}
		Assertions.assertNull(useTokens.get(filePath));
		Assertions.assertNull(useTokens.get(targetPath));
	}

	@Test
	@DisplayName("Moving does nothing on closed token")
	public void testMoveClosed() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var targetPath = tmpDir.resolve("inUse2.file");
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = UseToken.createWithNewFile(filePath, useTokens)) {
			token.close();
			Awaitility.await().pollDelay(7, TimeUnit.SECONDS).timeout(10, TimeUnit.SECONDS).until(() -> true);


			token.move(targetPath);

			MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
			Assertions.assertNull(useTokens.get(filePath));
			Assertions.assertNull(useTokens.get(targetPath));
		}
	}
}
