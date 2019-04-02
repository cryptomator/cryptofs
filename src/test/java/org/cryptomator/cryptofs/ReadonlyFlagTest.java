package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
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
	private Path path = mock(Path.class);

	private CryptoFileSystemProperties properties = mock(CryptoFileSystemProperties.class);

	private ReadonlyFlag inTest;

	@BeforeEach
	public void setup() throws IOException {
		when(path.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		when(provider.getFileStore(path)).thenReturn(fileStore);
	}

	@Test
	public void testReadonlyFlagIsSetIfReadonlyIsSetOnProperties() throws IOException {
		when(properties.readonly()).thenReturn(true);

		inTest = new ReadonlyFlag(properties, path);

		Assertions.assertTrue(inTest.isSet());
	}

	@Test
	public void testReadonlyFlagIsSetIfReadonlyIsNotSetOnPropertiesAndFilestoreOfVaultIsReadonly() throws IOException {
		when(properties.readonly()).thenReturn(false);
		when(fileStore.isReadOnly()).thenReturn(true);

		inTest = new ReadonlyFlag(properties, path);

		Assertions.assertTrue(inTest.isSet());
	}

	@Test
	public void testReadonlyFlagIsNotSetIfReadonlyIsNotSetOnPropertiesAndFilestoreOfVaultIsNotReadonly() throws IOException {
		when(properties.readonly()).thenReturn(false);
		when(fileStore.isReadOnly()).thenReturn(false);

		inTest = new ReadonlyFlag(properties, path);

		Assertions.assertFalse(inTest.isSet());
	}

	@Test
	public void testAssertWritableThrowsIOExceptionIfReadonlyIsSetOnProperties() throws IOException {
		when(properties.readonly()).thenReturn(true);

		inTest = new ReadonlyFlag(properties, path);

		Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
			inTest.assertWritable();
		});
	}

	@Test
	public void testAssertWritableThrowsIOExceptionIfReadonlyIsNotSetOnPropertiesAndFilestoreOfVaultIsReadonly() throws IOException {
		when(properties.readonly()).thenReturn(false);
		when(fileStore.isReadOnly()).thenReturn(true);

		inTest = new ReadonlyFlag(properties, path);

		Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
			inTest.assertWritable();
		});
	}

	@Test
	public void testAssertWritableDoesNotThrowIOExceptionIfReadonlyIsNotSetOnPropertiesAndFilestoreOfVaultIsNotReadonly() throws IOException {
		when(properties.readonly()).thenReturn(false);
		when(fileStore.isReadOnly()).thenReturn(false);

		inTest = new ReadonlyFlag(properties, path);

		inTest.assertWritable();
	}

}
