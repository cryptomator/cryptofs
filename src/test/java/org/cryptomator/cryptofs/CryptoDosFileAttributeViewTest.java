package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.spi.FileSystemProvider;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(Theories.class)
public class CryptoDosFileAttributeViewTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	private Path path = mock(Path.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private FileSystemProvider fileSystemProvider = mock(FileSystemProvider.class);
	private DosFileAttributeView delegate = mock(DosFileAttributeView.class);
	private ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);

	private CryptoFileAttributeProvider cryptoFileAttributeProvider = mock(CryptoFileAttributeProvider.class);

	private CryptoDosFileAttributeView inTest;

	@Before
	public void setup() throws UnsupportedFileAttributeViewException {
		when(path.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(fileSystemProvider);
		when(fileSystemProvider.getFileAttributeView(path, DosFileAttributeView.class)).thenReturn(delegate);

		inTest = new CryptoDosFileAttributeView(path, cryptoFileAttributeProvider, readonlyFlag);
	}

	@Test
	public void testNameIsDos() {
		assertThat(inTest.name(), is("dos"));
	}

	@Theory
	public void testSetReadOnly(boolean value) throws IOException {
		inTest.setReadOnly(value);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setReadOnly(value);
	}

	@Theory
	public void testSetHidden(boolean value) throws IOException {
		inTest.setHidden(value);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setHidden(value);
	}

	@Theory
	public void testSetSystem(boolean value) throws IOException {
		inTest.setSystem(value);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setSystem(value);
	}

	@Theory
	public void testSetArchive(boolean value) throws IOException {
		inTest.setArchive(value);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setArchive(value);
	}

}
