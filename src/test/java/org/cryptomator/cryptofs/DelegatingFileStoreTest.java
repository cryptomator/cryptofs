package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.attribute.FileStoreAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class DelegatingFileStoreTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	public ExpectedException thrown = ExpectedException.none();

	private FileStore delegate = mock(FileStore.class);

	private DelegatingFileStore inTest = new DelegatingFileStore(delegate);

	@Test
	public void testNameReturnsDelegateNamePrependedWithClassName() {
		when(delegate.name()).thenReturn("delegateName");

		assertThat(inTest.name(), is("DelegatingFileStore_delegateName"));
	}

	@Test
	public void testTypeIsClassName() {
		assertThat(inTest.type(), is("DelegatingFileStore"));
	}

	@Test
	public void testIsReadOnlyWithTrue() {
		when(delegate.isReadOnly()).thenReturn(true);

		assertThat(inTest.isReadOnly(), is(true));
	}

	@Test
	public void testIsReadOnlyWithFalse() {
		when(delegate.isReadOnly()).thenReturn(false);

		assertThat(inTest.isReadOnly(), is(false));
	}

	@Test
	public void testGetTotalSpace() throws IOException {
		when(delegate.getTotalSpace()).thenReturn(1337L);

		assertThat(inTest.getTotalSpace(), is(1337L));
	}

	@Test
	public void testGetUsableSpace() throws IOException {
		when(delegate.getUsableSpace()).thenReturn(1337L);

		assertThat(inTest.getUsableSpace(), is(1337L));
	}

	@Test
	public void testGetUnallocatedSpace() throws IOException {
		when(delegate.getUnallocatedSpace()).thenReturn(1337L);

		assertThat(inTest.getUnallocatedSpace(), is(1337L));
	}

	@Test
	public void testSupportsFileAttributeViewWithTrue() {
		when(delegate.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);

		assertThat(inTest.supportsFileAttributeView(PosixFileAttributeView.class), is(true));
	}

	@Test
	public void testSupportsFileAttributeViewWithFalse() {
		when(delegate.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(false);

		assertThat(inTest.supportsFileAttributeView(PosixFileAttributeView.class), is(false));
	}

	@Test
	public void testSupportsFileAttributeViewByNameWithTrue() {
		when(delegate.supportsFileAttributeView("abc")).thenReturn(true);

		assertThat(inTest.supportsFileAttributeView("abc"), is(true));
	}

	@Test
	public void testSupportsFileAttributeViewByNameWithFalse() {
		when(delegate.supportsFileAttributeView("abc")).thenReturn(false);

		assertThat(inTest.supportsFileAttributeView("abc"), is(false));
	}

	@Test
	public void getFileStoreAttributeView() {
		assertThat(delegate.getFileStoreAttributeView(FileStoreAttributeView.class), is((FileStoreAttributeView) null));
	}

	@Test
	public void testGetAttribute() throws IOException {
		thrown.expect(UnsupportedOperationException.class);

		delegate.getAttribute("any");
	}

}
