package org.cryptomator.cryptofs.inuse;

import org.cryptomator.cryptofs.fh.FileAlreadyInUseException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

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
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap);
		var inUseSpy = spy(inUseManager);

		var result = inUseSpy.isInUseByOthers(ciphertextPath);

		Assertions.assertFalse(result);
		verify(inUseSpy, never()).isInUseInternal(inUseFilePath);
	}

	@Test
	@DisplayName("Call internal inUse check, when map does not contain path")
	public void testUseByOthers() throws IOException {
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor);
		var inUseSpy = spy(inUseManager);
		doReturn(true).when(inUseSpy).isInUseInternal(inUseFilePath);

		inUseSpy.isInUseByOthers(ciphertextPath);

		verify(inUseSpy).isInUseInternal(inUseFilePath);
	}

	@ParameterizedTest
	@DisplayName("If internalUse check fails with declared exception, return false")
	@ValueSource(classes = {IllegalArgumentException.class, IOException.class})
	public void testUseByOthersException(Class exceptionClass) throws IOException {
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor);
		var inUseSpy = spy(inUseManager);
		doThrow(exceptionClass).when(inUseSpy).isInUseInternal(inUseFilePath);

		var result = Assertions.assertDoesNotThrow(() -> inUseSpy.isInUseByOthers(ciphertextPath));
		Assertions.assertFalse(result);
		verify(inUseSpy).isInUseInternal(inUseFilePath);
	}

	@Test
	@DisplayName("\"use\" method places puts path into map and returns token")
	public void testUsePlacesPathInMap() throws FileAlreadyInUseException {
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
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap);
		var inUseSpy = spy(inUseManager);
		var token = mock(RealUseToken.class);

		try (var staticUseTokenMock = mockStatic(RealUseToken.class)) {
			staticUseTokenMock.when(() -> RealUseToken.createWithExistingFile(inUseFilePath, "cryptobot3000", preparedMap)).thenReturn(token);
			doReturn(false).when(inUseSpy).isInUseInternal(inUseFilePath);

			var result = inUseSpy.createInternal(inUseFilePath);
			Assertions.assertSame(token, result);
			verify(inUseSpy).isInUseInternal(inUseFilePath);
			staticUseTokenMock.verify(() -> RealUseToken.createWithExistingFile(inUseFilePath, "cryptobot3000", preparedMap));
		}
	}

	@Test
	@DisplayName("Create internal with INVALID in-use-file")
	public void testCreateExistingInvalid() throws IOException {
		var preparedMap = new ConcurrentHashMap<Path, RealUseToken>();
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap);
		var inUseSpy = spy(inUseManager);
		var token = mock(RealUseToken.class);

		try (var staticUseTokenMock = mockStatic(RealUseToken.class)) {
			staticUseTokenMock.when(() -> RealUseToken.createWithInvalidFile(inUseFilePath, "cryptobot3000", preparedMap)).thenReturn(token);
			doThrow(IllegalArgumentException.class).when(inUseSpy).isInUseInternal(inUseFilePath);

			var result = inUseSpy.createInternal(inUseFilePath);
			Assertions.assertSame(token, result);
			verify(inUseSpy).isInUseInternal(inUseFilePath);
			staticUseTokenMock.verify(() -> RealUseToken.createWithInvalidFile(inUseFilePath, "cryptobot3000", preparedMap));
		}
	}

	@Test
	@DisplayName("Create internal with NOT existing in-use-file")
	public void testCreateNotExisting() throws IOException {
		var preparedMap = new ConcurrentHashMap<Path, RealUseToken>();
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap);
		var inUseSpy = spy(inUseManager);
		var token = mock(RealUseToken.class);

		try (var staticUseTokenMock = mockStatic(RealUseToken.class)) {
			staticUseTokenMock.when(() -> RealUseToken.createWithNewFile(inUseFilePath, "cryptobot3000", preparedMap)).thenReturn(token);
			doThrow(NoSuchFileException.class).when(inUseSpy).isInUseInternal(inUseFilePath);

			var result = inUseSpy.createInternal(inUseFilePath);
			Assertions.assertSame(token, result);
			verify(inUseSpy).isInUseInternal(inUseFilePath);
			staticUseTokenMock.verify(() -> RealUseToken.createWithNewFile(inUseFilePath, "cryptobot3000", preparedMap));
		}
	}

	@Test
	@DisplayName("Create internal throws UncheckedIO(FileAlreadyInUse) exception")
	public void testCreateFailedRead() throws IOException {
		var preparedMap = new ConcurrentHashMap<Path, RealUseToken>();
		var inUseManager = new RealInUseManager("cryptobot3000", cryptor, preparedMap);
		var inUseSpy = spy(inUseManager);

		doReturn(true).when(inUseSpy).isInUseInternal(inUseFilePath);

		var actualException = Assertions.assertThrows(UncheckedIOException.class, () -> inUseSpy.createInternal(inUseFilePath));

		Assertions.assertInstanceOf(FileAlreadyInUseException.class, actualException.getCause());
		verify(inUseSpy).isInUseInternal(inUseFilePath);
	}

	//TODO: test createInvalid
	//TODO: test validate
	//TODO: test readInUseFile

	@AfterEach
	public void afterEach() {
		staticManagerMock.close();
	}
}
