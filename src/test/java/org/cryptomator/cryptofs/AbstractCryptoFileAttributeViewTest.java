package org.cryptomator.cryptofs;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.spi.FileSystemProvider;

import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(Theories.class)
public class AbstractCryptoFileAttributeViewTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private Path path = mock(Path.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private FileSystemProvider fileSystemProvider = mock(FileSystemProvider.class);

	@Test
	public void testConstructorFailsIfDelegateIsNotAvailable() throws UnsupportedFileAttributeViewException {
		when(path.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(fileSystemProvider);
		when(fileSystemProvider.getFileAttributeView(path, DosFileAttributeView.class)).thenReturn(null);

		thrown.expect(UnsupportedFileAttributeViewException.class);

		new AbstractCryptoFileAttributeView<DosFileAttributes, DosFileAttributeView>(path, null, DosFileAttributes.class, DosFileAttributeView.class) {
			@Override
			public String name() {
				return null;
			}

		};
	}

}
