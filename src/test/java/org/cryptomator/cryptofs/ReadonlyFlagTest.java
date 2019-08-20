package org.cryptomator.cryptofs;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.ReadOnlyFileSystemException;
import java.nio.file.spi.FileSystemProvider;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ReadonlyFlagTest {

	private FileStore fileStore = mock(FileStore.class);
	private FileSystemProvider provider = mock(FileSystemProvider.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private Path path = mock(Path.class, "test-path");

	private CryptoFileSystemProperties properties = mock(CryptoFileSystemProperties.class);

	@BeforeEach
	public void setup() throws IOException {
		when(path.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		when(provider.getFileStore(path)).thenReturn(fileStore);
	}

	@DisplayName("isSet()")
	@ParameterizedTest(name = "readonlyFlag: {0}, writeProtected: {1} -> mounted readonly {2}")
	@CsvSource({
			"false, false, false",
			"true, false, true",
			"false, true, true",
			"true, true, true",
	})
	public void testIsSet(boolean readonlyFlag, boolean writeProtected, boolean expectedResult) throws IOException {
		when(properties.readonly()).thenReturn(readonlyFlag);
		if (writeProtected) {
			Mockito.doThrow(new AccessDeniedException(path.toString())).when(provider).checkAccess(path, AccessMode.WRITE);
		}
		ReadonlyFlag inTest = new ReadonlyFlag(properties, path);

		boolean result = inTest.isSet();

		MatcherAssert.assertThat(result, CoreMatchers.is(expectedResult));
		Assertions.assertEquals(expectedResult, result);
	}

	@DisplayName("assertWritable()")
	@ParameterizedTest(name = "readonlyFlag: {0}, writeProtected: {1} -> mounted readonly {2}")
	@CsvSource({
			"false, false, false",
			"true, false, true",
			"false, true, true",
			"true, true, true",
	})
	public void testAssertWritable(boolean readonlyFlag, boolean writeProtected, boolean expectedResult) throws IOException {
		when(properties.readonly()).thenReturn(readonlyFlag);
		if (writeProtected) {
			Mockito.doThrow(new AccessDeniedException(path.toString())).when(provider).checkAccess(path, AccessMode.WRITE);
		}
		ReadonlyFlag inTest = new ReadonlyFlag(properties, path);

		if (expectedResult) {
			Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
				inTest.assertWritable();
			});
		} else {
			Assertions.assertDoesNotThrow(() -> {
				inTest.assertWritable();
			});
		}
	}

}
