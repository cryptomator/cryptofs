package org.cryptomator.cryptofs;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.spi.FileSystemProvider;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class CryptoFileOwnerAttributeViewTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private Path path = mock(Path.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private FileSystemProvider provider = mock(FileSystemProvider.class);
	private FileOwnerAttributeView delegate = mock(FileOwnerAttributeView.class);
	private ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);

	private CryptoFileOwnerAttributeView inTest;

	@Before
	public void setup() throws UnsupportedFileAttributeViewException {
		when(path.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		when(provider.getFileAttributeView(path, FileOwnerAttributeView.class)).thenReturn(delegate);

		inTest = new CryptoFileOwnerAttributeView(path, readonlyFlag);
	}

	@Test
	public void testConstructorThrowsUnsupportedFileAttributeViewExceptionIfViewIsNotSupported() throws UnsupportedFileAttributeViewException {
		when(provider.getFileAttributeView(path, FileOwnerAttributeView.class)).thenReturn(null);

		thrown.expect(UnsupportedFileAttributeViewException.class);

		new CryptoFileOwnerAttributeView(path, readonlyFlag);
	}

	@Test
	public void testNameReturnsOwner() {
		assertThat(inTest.name(), is("owner"));
	}

	@Test
	public void testGetOwnerDelegates() throws IOException {
		UserPrincipal principal = mock(UserPrincipal.class);
		when(delegate.getOwner()).thenReturn(principal);

		assertThat(inTest.getOwner(), is(principal));
	}

	@Test
	public void testSetOwnerDelegates() throws IOException {
		UserPrincipal principal = mock(UserPrincipal.class);

		inTest.setOwner(principal);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setOwner(principal);
	}

}
