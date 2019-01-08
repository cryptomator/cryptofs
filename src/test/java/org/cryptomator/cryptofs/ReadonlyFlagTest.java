package org.cryptomator.cryptofs;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.ReadOnlyFileSystemException;
import java.nio.file.spi.FileSystemProvider;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class ReadonlyFlagTest {

	private FileStore fileStore = mock(FileStore.class);
	private FileSystemProvider provider = mock(FileSystemProvider.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private Path path = mock(Path.class);

	private CryptoFileSystemProperties properties = mock(CryptoFileSystemProperties.class);

	private ReadonlyFlag inTest;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Before
	public void setup() throws IOException {
		when(path.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		when(provider.getFileStore(path)).thenReturn(fileStore);
	}

	@Test
	public void testReadonlyFlagIsSetIfReadonlyIsSetOnProperties() throws IOException {
		when(properties.readonly()).thenReturn(true);

		UncheckedThrows.allowUncheckedThrowsOf(IOException.class).from(() -> {
			inTest = new ReadonlyFlag(properties, path);
		});

		assertThat(inTest.isSet(), is(true));
	}

	@Test
	public void testReadonlyFlagIsSetIfReadonlyIsNotSetOnPropertiesAndFilestoreOfVaultIsReadonly() throws IOException {
		when(properties.readonly()).thenReturn(false);
		when(fileStore.isReadOnly()).thenReturn(true);

		UncheckedThrows.allowUncheckedThrowsOf(IOException.class).from(() -> {
			inTest = new ReadonlyFlag(properties, path);
		});

		assertThat(inTest.isSet(), is(true));
	}

	@Test
	public void testReadonlyFlagIsNotSetIfReadonlyIsNotSetOnPropertiesAndFilestoreOfVaultIsNotReadonly() throws IOException {
		when(properties.readonly()).thenReturn(false);
		when(fileStore.isReadOnly()).thenReturn(false);

		UncheckedThrows.allowUncheckedThrowsOf(IOException.class).from(() -> {
			inTest = new ReadonlyFlag(properties, path);
		});

		assertThat(inTest.isSet(), is(false));
	}

	@Test
	public void testAssertWritableThrowsIOExceptionIfReadonlyIsSetOnProperties() throws IOException {
		when(properties.readonly()).thenReturn(true);

		UncheckedThrows.allowUncheckedThrowsOf(IOException.class).from(() -> {
			inTest = new ReadonlyFlag(properties, path);
		});

		thrown.expect(ReadOnlyFileSystemException.class);

		inTest.assertWritable();
	}

	@Test
	public void testAssertWritableThrowsIOExceptionIfReadonlyIsNotSetOnPropertiesAndFilestoreOfVaultIsReadonly() throws IOException {
		when(properties.readonly()).thenReturn(false);
		when(fileStore.isReadOnly()).thenReturn(true);

		UncheckedThrows.allowUncheckedThrowsOf(IOException.class).from(() -> {
			inTest = new ReadonlyFlag(properties, path);
		});

		thrown.expect(ReadOnlyFileSystemException.class);

		inTest.assertWritable();
	}

	@Test
	public void testAssertWritableDoesNotThrowIOExceptionIfReadonlyIsNotSetOnPropertiesAndFilestoreOfVaultIsNotReadonly() throws IOException {
		when(properties.readonly()).thenReturn(false);
		when(fileStore.isReadOnly()).thenReturn(false);

		UncheckedThrows.allowUncheckedThrowsOf(IOException.class).from(() -> {
			inTest = new ReadonlyFlag(properties, path);
		});

		inTest.assertWritable();
	}

}
