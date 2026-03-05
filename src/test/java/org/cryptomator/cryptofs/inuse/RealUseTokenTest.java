package org.cryptomator.cryptofs.inuse;

import org.awaitility.Awaitility;
import org.cryptomator.cryptolib.api.Cryptor;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.opentest4j.AssertionFailedError;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchService;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class RealUseTokenTest {

	private ConcurrentMap<Path, RealUseToken> useTokens;
	private Cryptor cryptor;
	private RealUseToken.EncryptionDecorator encWrapper;
	private Executor tokenPersistor;
	@TempDir
	Path tmpDir;
	private WatchService watchService;
	private static final int CREATION_DELAY_MILLIS = 1000;
	private static final Duration FILE_OPERATION_DELAY = Duration.ofMillis(CREATION_DELAY_MILLIS - 100L); //allow some leeway
	private static final Duration FILE_OPERATION_MAX = FILE_OPERATION_DELAY.plusMillis(2000L);

	@BeforeEach
	public void beforeEach() throws IOException {
		cryptor = mock(Cryptor.class);
		encWrapper = mock(RealUseToken.EncryptionDecorator.class);
		useTokens = new ConcurrentHashMap<>();
		watchService = tmpDir.getFileSystem().newWatchService();
		tokenPersistor = Executors.newVirtualThreadPerTaskExecutor();
		doAnswer(invocation -> invocation.getArgument(0)) //just return the real file channel
				.when(encWrapper).wrapWithEncryption(any(), eq(cryptor));
	}

	@AfterEach
	public void afterEach() {
		try {
			watchService.close();
		} catch (IOException _) {
			//no-op
		}
	}

	private static void assertInUseFile(String expectedOwner, Path filePath) throws AssertionFailedError {
		var props = new Properties();
		var rawProps = Assertions.assertDoesNotThrow(() -> Files.readAllBytes(filePath));
		Assertions.assertDoesNotThrow(() -> props.load(new ByteArrayInputStream(rawProps)));
		Assertions.assertEquals(expectedOwner, props.getProperty(UseToken.OWNER_KEY));
		Assertions.assertDoesNotThrow(() -> Instant.parse(props.getProperty(UseToken.LASTUPDATED_KEY)));
	}

	@RepeatedTest(5)
	@DisplayName("Creating a token creates valid inUse file and on close is deleted")
	public void testValidFileContent() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.CREATE_NEW, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY) //
					.atMost(FILE_OPERATION_MAX) //
					.untilAsserted(() -> assertInUseFile("test3000", filePath));
		}
		Assertions.assertTrue(Files.notExists(filePath));
	}

	@Test
	@DisplayName("After X seconds of token creation, a file is updated")
	public void testFileSteal() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		Files.createFile(filePath);
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
		var fileTime = Files.getLastModifiedTime(filePath);

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.TRUNCATE_EXISTING, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX).until(() -> fileTime.compareTo(Files.getLastModifiedTime(filePath)) < 0);
			var events = watchKey.pollEvents();
			var createEvent = events.stream().filter(e -> e.kind().equals(StandardWatchEventKinds.ENTRY_MODIFY)).findAny();
			Assertions.assertTrue(createEvent.isPresent());
			createEvent.ifPresent(e -> {
				Assertions.assertTrue(filePath.endsWith((Path) e.context()));
			});
		}
		Assertions.assertTrue(Files.notExists(filePath));
	}

	@Test
	@DisplayName("After X seconds of token creation, failed steal closes the token ")
	public void testFileStealFails() throws IOException {
		var filePath = tmpDir.resolve("inUse.file"); //file does not exist
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.TRUNCATE_EXISTING, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX).until(token::isClosed);
			Assertions.assertTrue(Files.notExists(filePath));
			Assertions.assertTrue(token.isClosed());
		}
		MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
	}

	@Test
	@DisplayName("Closing a UseToken before X seconds passed skips file creation")
	public void testTokenCloseBeforeFileOperation() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		RealUseToken token;
		try (var t = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.CREATE_NEW, encWrapper)) {
			token = t;
			Assertions.assertFalse(t.isClosed());
		}
		Assertions.assertTrue(token.isClosed());
		Awaitility.await().pollDelay(FILE_OPERATION_MAX).until(() -> true);
		Assertions.assertTrue(Files.notExists(filePath));
		MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
	}

	@Test
	@DisplayName("Moving a token before file creation")
	public void testMoveToBefore() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var targetPath = tmpDir.resolve("inUse2.file");
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.CREATE_NEW, encWrapper)) {
			token.moveToInternal(targetPath);

			//no file operation after move
			MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
			// target file exists
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX) //
					.untilAsserted(() -> assertInUseFile("test3000", targetPath));
			//original filePath does not exist
			Assertions.assertTrue(Files.notExists(filePath));

			//only targetPath was created
			var events = watchKey.pollEvents();
			var createEvent = events.stream().filter(e -> e.kind().equals(StandardWatchEventKinds.ENTRY_CREATE)).findAny();
			Assertions.assertTrue(createEvent.isPresent());
			createEvent.ifPresent(e -> {
				Assertions.assertEquals(1, e.count());
				Assertions.assertTrue(targetPath.endsWith((Path) e.context()));
			});
		}
		Assertions.assertNull(useTokens.get(targetPath));
	}

	@Test
	@DisplayName("Moving a token after file creation")
	public void testMoveToAfter() {
		var filePath = tmpDir.resolve("inUseMove.file");
		var targetPath = tmpDir.resolve("inUseMove2.file");

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.CREATE_NEW, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX) //
					.untilAsserted(() -> assertInUseFile("test3000", filePath));

			token.moveToInternal(targetPath);

			// target file will be created
			// orginal filePath does not exist, target exists
			Assertions.assertTrue(Files.notExists(filePath), "inUse.file still exists after move");
			Assertions.assertTrue(Files.exists(targetPath), "inUse2.file does not exist after move");
			Assertions.assertNotNull(useTokens.get(targetPath));
		}
		Assertions.assertNull(useTokens.get(targetPath));
	}

	@Test
	@DisplayName("Moving does nothing on never-persisted, closed token")
	public void testMoveToNeverPersistedClosed() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var targetPath = tmpDir.resolve("inUse2.file");
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.CREATE_NEW, encWrapper)) {
			token.close();

			token.moveToInternal(targetPath);

			MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
			Assertions.assertNull(useTokens.get(targetPath));
		}
	}

	@Test
	@DisplayName("Moving does nothing on persisted-but-closed token")
	public void testMoveToClosed() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");
		var targetPath = tmpDir.resolve("inUse2.file");
		var watchKey = tmpDir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.CREATE_NEW, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX) //
					.untilAsserted(() -> assertInUseFile("test3000", filePath));
			watchKey.pollEvents(); //clear watchEvents
			token.close();
			Awaitility.await().atMost(FILE_OPERATION_MAX) //
					.until(() -> !watchKey.pollEvents().isEmpty());

			token.moveToInternal(targetPath);

			MatcherAssert.assertThat(watchKey.pollEvents(), Matchers.empty());
			Assertions.assertNull(useTokens.get(targetPath));
		}
	}

	@Test
	@DisplayName("After token persisting, refreshing a token modifies content")
	public void testFileRefresh() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.CREATE_NEW, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX) //
					.untilAsserted(() -> assertInUseFile("test3000", filePath));

			var props = new Properties();
			var rawProps = Files.readAllBytes(filePath);
			props.load(new ByteArrayInputStream(rawProps));
			var oldLastUpdated = Instant.parse(props.getProperty(UseToken.LASTUPDATED_KEY));

			token.refresh();

			var props2 = new Properties();
			rawProps = Files.readAllBytes(filePath);
			props2.load(new ByteArrayInputStream(rawProps));

			Assertions.assertEquals("test3000", props2.getProperty(UseToken.OWNER_KEY));
			var newLastUpdated = Instant.parse(props2.getProperty(UseToken.LASTUPDATED_KEY));
			Assertions.assertTrue(newLastUpdated.isAfter(oldLastUpdated));
		}
	}

	@Test
	@DisplayName("Refreshing a token with not-matching last-modified date closes token, but does not delete file ")
	public void testFileRefreshWrongLastModified() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.CREATE_NEW, encWrapper)) {
			Awaitility.await().atLeast(FILE_OPERATION_DELAY).atMost(FILE_OPERATION_MAX) //
					.untilAsserted(() -> assertInUseFile("test3000", filePath));

			Files.setLastModifiedTime(filePath, FileTime.from(Instant.ofEpochMilli(0)));

			token.refresh();

			Assertions.assertTrue(token.isClosed());
			Assertions.assertTrue(Files.exists(filePath));
		}
		Assertions.assertTrue(Files.exists(filePath));
	}

	@Test
	@DisplayName("Before token persisting, refreshing a token does nothing")
	public void testFileRefreshSkip() throws IOException {
		var filePath = tmpDir.resolve("inUse.file");

		try (var token = new RealUseToken(filePath, "test3000", cryptor, useTokens, tokenPersistor, CREATION_DELAY_MILLIS, StandardOpenOption.CREATE_NEW, encWrapper)) {
			token.refresh();
			verify(encWrapper, never()).wrapWithEncryption(any(), eq(cryptor));
		}
	}
}
