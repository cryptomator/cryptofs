package org.cryptomator.cryptofs.inuse;

import org.awaitility.Awaitility;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Cryptor;
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
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

public class RealUseTokenTest {

	private ConcurrentMap<Path, RealUseToken> useTokens;
	private Cryptor cryptor;
	private RealUseToken.EncryptionDecorator encWrapper;
	@TempDir
	Path tmpDir;
	private WatchService watchService;

	private final static Duration FILE_OPERATION_DELAY = Duration.ofMillis(Constants.INUSE_DELAY_MILLIS - 100);
	private final static Duration FILE_OPERATION_MAX = FILE_OPERATION_DELAY.plusMillis(3000);

	@BeforeEach
	public void beforeEach() throws IOException {
		cryptor = mock(Cryptor.class);
		encWrapper = mock(RealUseToken.EncryptionDecorator.class);
		useTokens = new ConcurrentHashMap<>();//Mockito.mock(ConcurrentMap.class);
		watchService = tmpDir.getFileSystem().newWatchService();

		doAnswer(invocation -> invocation.getArgument(0)) //just return the real file channel
				.when(encWrapper).wrapWithEncryption(any(), eq(cryptor));
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
		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, RealUseToken.ActivationType.CREATE, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX).until(() -> Files.exists(filePath));
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

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, RealUseToken.ActivationType.UPDATE, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX).until(() -> fileTime.compareTo(Files.getLastModifiedTime(filePath)) < 0);
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
	@DisplayName("Invalid token creation does nothing")
	public void testInvalid() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, RealUseToken.ActivationType.NONE, encWrapper)) {
			Awaitility.await().pollDelay(FILE_OPERATION_MAX).timeout(FILE_OPERATION_MAX.multipliedBy(2)).until(() -> true);
			Assertions.assertTrue(Files.notExists(filePath));
			Assertions.assertTrue(token.isClosed());
			Assertions.assertNull(useTokens.get(filePath));
			MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
		}
	}

	@Test
	@DisplayName("After 5 seconds of token creation, failed steal closes the token ")
	public void testFileStealFails() throws IOException {
		var filePath = tmpDir.resolve("inUse.file"); //file does not exist
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, RealUseToken.ActivationType.STEAL, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX).until(token::isClosed);
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

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, RealUseToken.ActivationType.CREATE, encWrapper)) {
			Assertions.assertTrue(Files.notExists(filePath));
		}
		Awaitility.await().pollDelay(FILE_OPERATION_MAX).timeout(FILE_OPERATION_MAX.multipliedBy(2)).until(() -> true);
		Assertions.assertTrue(Files.notExists(filePath));
		Assertions.assertNull(useTokens.get(filePath));
		MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
	}

	@Test
	@DisplayName("Moving a token before file creation")
	public void testMoveToBefore() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var targetPath = tmpDir.resolve("inUse2.file");
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, RealUseToken.ActivationType.CREATE, encWrapper)) {
			token.moveToInternal(targetPath);

			//no file operation after move
			MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
			// target file will be created
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX).until(() -> Files.exists(targetPath));
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
	public void testMoveToAfter() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var targetPath = tmpDir.resolve("inUse2.file");

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, RealUseToken.ActivationType.CREATE, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX).until(() -> Files.exists(filePath));

			token.moveToInternal(targetPath);

			// target file will be created
			// orginal filePath does not exist, target exists
			Assertions.assertTrue(Files.notExists(filePath), "inUse.file still exists after move");
			Assertions.assertTrue(Files.exists(targetPath), "inUse2.file does not exist after move");
			Assertions.assertNull(useTokens.get(filePath));
			Assertions.assertNotNull(useTokens.get(targetPath));
		}
		Assertions.assertNull(useTokens.get(filePath));
		Assertions.assertNull(useTokens.get(targetPath));
	}

	@Test
	@DisplayName("Moving does nothing on closed token")
	public void testMoveToClosed() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var targetPath = tmpDir.resolve("inUse2.file");
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, RealUseToken.ActivationType.CREATE, encWrapper)) {
			token.close();
			Awaitility.await().pollDelay(FILE_OPERATION_MAX).timeout(FILE_OPERATION_MAX.multipliedBy(2)).until(() -> true);


			token.moveToInternal(targetPath);

			MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
			Assertions.assertNull(useTokens.get(filePath));
			Assertions.assertNull(useTokens.get(targetPath));
		}
	}
}
