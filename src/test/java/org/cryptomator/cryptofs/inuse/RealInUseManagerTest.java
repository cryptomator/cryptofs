package org.cryptomator.cryptofs.inuse;

import com.github.benmanes.caffeine.cache.Cache;
import org.cryptomator.cryptofs.common.EncryptedChannels;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentMatcher;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class RealInUseManagerTest {

	private MockedStatic<RealInUseManager> staticManagerMock;
	private Path ciphertextPath;
	private Path inUseFilePath;
	private Cryptor cryptor;

	@BeforeEach
	public void beforeEach() {
		ciphertextPath = mock(Path.class, "ciphertext.c9r");
		inUseFilePath = mock(Path.class, "inUseFile.c9u");
		cryptor = mock(Cryptor.class);
		staticManagerMock = mockStatic(RealInUseManager.class);
		staticManagerMock.when(() -> RealInUseManager.computeInUseFilePath(ciphertextPath)).thenReturn(inUseFilePath);
	}

	@Test
	@DisplayName("If the useTokens map contains the path, return immediately with false")
	public void testUseByOthersWithExistingToken() throws IOException {
		var preparedMap = new ConcurrentHashMap<Path, RealUseToken>();
		preparedMap.put(inUseFilePath, mock(RealUseToken.class));
		var filesMarkedForStealing = mock(Cache.class);
		var useInfoCache = mock(Cache.class);
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap, filesMarkedForStealing, useInfoCache);
		var inUseSpy = spy(inUseManager);

		var result = inUseSpy.isInUseByOthers(ciphertextPath);

		Assertions.assertFalse(result);
		verify(inUseSpy, never()).isInUse(inUseFilePath);
	}

	@Test
	@DisplayName("Call internal inUse check, when map does not contain path")
	public void testUseByOthers() throws IOException {
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor);
		var inUseSpy = spy(inUseManager);
		doReturn(true).when(inUseSpy).isInUse(inUseFilePath);

		inUseSpy.isInUseByOthers(ciphertextPath);

		verify(inUseSpy).isInUse(inUseFilePath);
	}

	@ParameterizedTest
	@DisplayName("If internalUse check fails with declared exception, return false")
	@ValueSource(classes = {IllegalArgumentException.class, IOException.class})
	public void testUseByOthersException(Class exceptionClass) throws IOException {
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor);
		var inUseSpy = spy(inUseManager);
		doThrow(exceptionClass).when(inUseSpy).isInUse(inUseFilePath);

		var result = Assertions.assertDoesNotThrow(() -> inUseSpy.isInUseByOthers(ciphertextPath));
		Assertions.assertFalse(result);
		verify(inUseSpy).isInUse(inUseFilePath);
	}

	@Test
	@DisplayName("\"use\" method puts path into map and returns token")
	public void testUsePutsPathInMap() throws FileAlreadyInUseException {
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor);
		var inUseSpy = spy(inUseManager);
		var token = mock(RealUseToken.class);

		doReturn(token).when(inUseSpy).createInternal(inUseFilePath);

		var result = inUseSpy.use(ciphertextPath);
		Assertions.assertSame(token, result);
	}

	@Test
	@DisplayName("\"use\" method rethrow FileAlreadyInUseException")
	public void testUseThrows() throws FileAlreadyInUseException {
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor);
		var inUseSpy = spy(inUseManager);
		var inUseException = new FileAlreadyInUseException(inUseFilePath);

		doThrow(new UncheckedIOException(inUseException)).when(inUseSpy).createInternal(inUseFilePath);

		var exception = Assertions.assertThrows(FileAlreadyInUseException.class, () -> inUseSpy.use(ciphertextPath));
		Assertions.assertSame(inUseException, exception);
	}

	@Test
	@DisplayName("\"use\" method returns CLOSED_TOKEN on IOException")
	public void testUseClosedToken() throws FileAlreadyInUseException {
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor);
		var inUseSpy = spy(inUseManager);
		var someIOException = new IOException("it's over 9000!");

		doThrow(new UncheckedIOException(someIOException)).when(inUseSpy).createInternal(inUseFilePath);

		var result = Assertions.assertDoesNotThrow(() -> inUseSpy.use(ciphertextPath));
		Assertions.assertSame(UseToken.CLOSED_TOKEN, result);
	}

	@Test
	@DisplayName("Create internal with existing in-use-file")
	public void testCreateExistingValid() throws IOException {
		var preparedMap = new ConcurrentHashMap<Path, RealUseToken>();
		var ignoredInUseFiles = mock(Cache.class);
		doNothing().when(ignoredInUseFiles).invalidate(inUseFilePath);
		var useInfoCache = mock(Cache.class);
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap, ignoredInUseFiles, useInfoCache);
		var inUseSpy = spy(inUseManager);
		var token = mock(RealUseToken.class);

		try (var staticUseTokenMock = mockStatic(RealUseToken.class)) {
			staticUseTokenMock.when(() -> RealUseToken.createWithExistingFile(inUseFilePath, "cryptobot3000", cryptor, preparedMap)).thenReturn(token);
			doReturn(false).when(inUseSpy).isInUse(inUseFilePath);

			var result = inUseSpy.createInternal(inUseFilePath);
			Assertions.assertSame(token, result);
			verify(inUseSpy).isInUse(inUseFilePath);
			verify(ignoredInUseFiles).invalidate(inUseFilePath);
			staticUseTokenMock.verify(() -> RealUseToken.createWithExistingFile(inUseFilePath, "cryptobot3000", cryptor, preparedMap));
		}
	}

	@Test
	@DisplayName("Create internal with INVALID in-use-file")
	public void testCreateExistingInvalid() throws IOException {
		var preparedMap = new ConcurrentHashMap<Path, RealUseToken>();
		var ignoredFiles = mock(Cache.class);
		var useInfoCache = mock(Cache.class);
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap, ignoredFiles, useInfoCache);
		var inUseSpy = spy(inUseManager);
		var token = mock(RealUseToken.class);

		try (var staticUseTokenMock = mockStatic(RealUseToken.class)) {
			staticUseTokenMock.when(() -> RealUseToken.createWithExistingFile(inUseFilePath, "cryptobot3000", cryptor, preparedMap)).thenReturn(token);
			doThrow(IllegalArgumentException.class).when(inUseSpy).isInUse(inUseFilePath);

			var result = inUseSpy.createInternal(inUseFilePath);
			Assertions.assertSame(token, result);
			verify(inUseSpy).isInUse(inUseFilePath);
			staticUseTokenMock.verify(() -> RealUseToken.createWithExistingFile(inUseFilePath, "cryptobot3000", cryptor, preparedMap));
		}
	}

	@Test
	@DisplayName("Create internal with NOT existing in-use-file")
	public void testCreateNotExisting() throws IOException {
		var preparedMap = new ConcurrentHashMap<Path, RealUseToken>();
		var ignoredFiles = mock(Cache.class);
		var useInfoCache = mock(Cache.class);
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap, ignoredFiles, useInfoCache);
		var inUseSpy = spy(inUseManager);
		var token = mock(RealUseToken.class);

		try (var staticUseTokenMock = mockStatic(RealUseToken.class)) {
			staticUseTokenMock.when(() -> RealUseToken.createWithNewFile(inUseFilePath, "cryptobot3000", cryptor, preparedMap)).thenReturn(token);
			doThrow(NoSuchFileException.class).when(inUseSpy).isInUse(inUseFilePath);

			var result = inUseSpy.createInternal(inUseFilePath);
			Assertions.assertSame(token, result);
			verify(inUseSpy).isInUse(inUseFilePath);
			staticUseTokenMock.verify(() -> RealUseToken.createWithNewFile(inUseFilePath, "cryptobot3000", cryptor, preparedMap));
		}
	}

	@Test
	@DisplayName("Create internal throws UncheckedIO(FileAlreadyInUse) exception")
	public void testCreateFailedRead() throws IOException {
		var preparedMap = new ConcurrentHashMap<Path, RealUseToken>();
		var ignoredFiles = mock(Cache.class);
		var useInfoCache = mock(Cache.class);
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap, ignoredFiles, useInfoCache);
		var inUseSpy = spy(inUseManager);

		doReturn(true).when(inUseSpy).isInUse(inUseFilePath);

		var actualException = Assertions.assertThrows(UncheckedIOException.class, () -> inUseSpy.createInternal(inUseFilePath));

		Assertions.assertInstanceOf(FileAlreadyInUseException.class, actualException.getCause());
		verify(inUseSpy).isInUse(inUseFilePath);
	}

	@Nested
	class ReadInUseFile {

		MockedStatic<EncryptedChannels> staticEncryptionMock;

		@BeforeEach
		void beforeEach(@TempDir Path tempDir) {
			inUseFilePath = tempDir.resolve("inUse.file");
			staticEncryptionMock = mockStatic(EncryptedChannels.class);

			var fileContentCryptor = mock(FileContentCryptor.class);
			when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
			when(fileContentCryptor.cleartextChunkSize()).thenReturn(42);
		}

		@Test
		@DisplayName("Reading existing inUse-file reads from file, convert to Properties and validates them")
		void SuccessTest() throws IOException {
			Files.createFile(inUseFilePath);
			var inUseManager = new RealInUseManager("cryptobot3000", cryptor);
			var inUseSpy = spy(inUseManager);

			MockedConstruction.MockInitializer<Properties> propsMockInit = (props, context) -> {
				doNothing().when(props).load((InputStream) any());
			};
			try (MockedConstruction<Properties> constructorProps = mockConstruction(Properties.class, propsMockInit)) {
				var decryptingChannel = mock(DecryptingReadableByteChannel.class);
				doReturn(42).when(decryptingChannel).read(any());
				staticEncryptionMock.when(() -> EncryptedChannels.wrapDecryptionAround(any(), eq(cryptor))).thenReturn(decryptingChannel);

				inUseSpy.readInUseFile(inUseFilePath);

				Properties props = constructorProps.constructed().getFirst();
				verify(decryptingChannel).read(any());

				ArgumentMatcher<InputStream> hasCorrectStreamSize = s -> {
					try {
						return s.available() == 42;
					} catch (IOException e) {
						throw new RuntimeException(e);
					}
				};
				verify(props).load(argThat(hasCorrectStreamSize));
			}
		}

		@Test
		@DisplayName("Not existing inUse-file throws NoSuchFileException")
		void notExistingFile() {
			var inUseManager = new RealInUseManager("cryptobot3000", cryptor);
			var inUseSpy = spy(inUseManager);
			Assertions.assertThrows(NoSuchFileException.class, () -> inUseSpy.readInUseFile(inUseFilePath));
		}

		@Test
		@DisplayName("Empty inUse-file throws IllegalArgumentException")
		void emptyFile() throws IOException {
			var inUseManager = new RealInUseManager("cryptobot3000", cryptor);
			var inUseSpy = spy(inUseManager);

			Files.createFile(inUseFilePath);

			var decryptingChannel = mock(DecryptingReadableByteChannel.class);
			doReturn(-1).when(decryptingChannel).read(any());
			staticEncryptionMock.when(() -> EncryptedChannels.wrapDecryptionAround(any(), eq(cryptor))).thenReturn(decryptingChannel);

			Assertions.assertThrows(IllegalArgumentException.class, () -> inUseSpy.readInUseFile(inUseFilePath));
		}

		@AfterEach
		public void afterEach() {
			staticEncryptionMock.close();
		}
	}

	@Nested
	class IsInUseUseInfo {

		@Test
		@DisplayName("If the inUse properties have the same owner as the fs, return false")
		void hasSameOwner() {
			var useInfo = new InUseManager.UseInfo("cryptobot3000", Instant.now());
			var inUseManager = new RealInUseManager("cryptobot3000", cryptor);

			var result = inUseManager.isInUse(useInfo);

			Assertions.assertFalse(result, "isInUse returns true, but the owner is the same!");
		}

		@Test
		@DisplayName("If the inUse properties have the lastUpdated timestamp below threshold, return true")
		void hasDifferentOwnerLastUpdatedBelowTreshold() {
			var useInfo = new InUseManager.UseInfo("bob",Instant.now().minus(3, ChronoUnit.MINUTES));
			var inUseManager = new RealInUseManager("cryptobot3000", cryptor);

			var result = inUseManager.isInUse(useInfo);

			Assertions.assertTrue(result, "isInUse returns false, but lastUpdated is below threshold!");
		}

		@Test
		@DisplayName("If the inUse properties have the lastUpdated timestamp above threshold, return true")
		void hasDifferentOwnerLastUpdatedAboveThreshold() {
			var useInfo = new InUseManager.UseInfo("bob",Instant.now().minus(20, ChronoUnit.MINUTES));
			var inUseManager = new RealInUseManager("cryptobot3000", cryptor);

			var result = inUseManager.isInUse(useInfo);

			Assertions.assertFalse(result, "isInUse returns true, but lastUpdated is above threshold!");
		}

	}

	@Test
	@DisplayName("isInUse checks ignoredCache")
	void isInUseChecksIgnoredCache() throws IOException {
		var preparedMap = new ConcurrentHashMap<Path, RealUseToken>();
		var ignoredInUseFiles = mock(Cache.class);
		var useInfoCache = mock(Cache.class);
		doReturn(Boolean.TRUE).when(ignoredInUseFiles).getIfPresent(inUseFilePath);
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap, ignoredInUseFiles, useInfoCache);

		var result = inUseManager.isInUse(inUseFilePath);

		Assertions.assertFalse(result);
		verify(ignoredInUseFiles).getIfPresent(inUseFilePath);
	}

	@Test
	@DisplayName("isInUse checks useInfo cache")
	void isInUseChecksUseInfoCache() throws IOException {
		var preparedMap = new ConcurrentHashMap<Path, RealUseToken>();
		var ignoredInUseFiles = mock(Cache.class);
		doReturn(null).when(ignoredInUseFiles).getIfPresent(inUseFilePath);
		var useInfoCache = mock(Cache.class);
		var useInfo = new InUseManager.UseInfo("bob", Instant.now());
		doReturn(useInfo).when(useInfoCache).get(eq(inUseFilePath), any());
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap, ignoredInUseFiles, useInfoCache);

		var result = inUseManager.isInUse(inUseFilePath);

		Assertions.assertTrue(result);
		verify(useInfoCache).get(eq(inUseFilePath), any());
	}

	//TODO: test validate

	@AfterEach
	public void afterEach() {
		staticManagerMock.close();
	}
}
