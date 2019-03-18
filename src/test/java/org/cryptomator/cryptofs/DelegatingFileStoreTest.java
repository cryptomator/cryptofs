package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.attribute.FileStoreAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DelegatingFileStoreTest {

	private FileStore delegate = mock(FileStore.class);

	private DelegatingFileStore inTest = new DelegatingFileStore(delegate);

	@Test
	public void testNameReturnsDelegateNamePrependedWithClassName() {
		when(delegate.name()).thenReturn("delegateName");

		Assertions.assertEquals("DelegatingFileStore_delegateName", inTest.name());
	}

	@Test
	public void testTypeIsClassName() {
		Assertions.assertEquals("DelegatingFileStore", inTest.type());
	}

	@Test
	public void testIsReadOnlyWithTrue() {
		when(delegate.isReadOnly()).thenReturn(true);

		Assertions.assertTrue(inTest.isReadOnly());
	}

	@Test
	public void testIsReadOnlyWithFalse() {
		when(delegate.isReadOnly()).thenReturn(false);

		Assertions.assertFalse(inTest.isReadOnly());
	}

	@Test
	public void testGetTotalSpace() throws IOException {
		when(delegate.getTotalSpace()).thenReturn(1337L);

		Assertions.assertEquals(1337l, inTest.getTotalSpace());
	}

	@Test
	public void testGetUsableSpace() throws IOException {
		when(delegate.getUsableSpace()).thenReturn(1337L);

		Assertions.assertEquals(1337l, inTest.getUsableSpace());
	}

	@Test
	public void testGetUnallocatedSpace() throws IOException {
		when(delegate.getUnallocatedSpace()).thenReturn(1337L);

		Assertions.assertEquals(1337l, inTest.getUnallocatedSpace());
	}

	@Test
	public void testSupportsFileAttributeViewWithTrue() {
		when(delegate.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);

		Assertions.assertTrue(inTest.supportsFileAttributeView(PosixFileAttributeView.class));
	}

	@Test
	public void testSupportsFileAttributeViewWithFalse() {
		when(delegate.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(false);

		Assertions.assertFalse(inTest.supportsFileAttributeView(PosixFileAttributeView.class));
	}

	@Test
	public void testSupportsFileAttributeViewByNameWithTrue() {
		when(delegate.supportsFileAttributeView("abc")).thenReturn(true);

		Assertions.assertTrue(inTest.supportsFileAttributeView("abc"));
	}

	@Test
	public void testSupportsFileAttributeViewByNameWithFalse() {
		when(delegate.supportsFileAttributeView("abc")).thenReturn(false);

		Assertions.assertFalse(inTest.supportsFileAttributeView("abc"));
	}

	@Test
	public void getFileStoreAttributeView() {
		Assertions.assertNull(inTest.getFileStoreAttributeView(FileStoreAttributeView.class));
	}

	@Test
	public void testGetAttribute() {
		Assertions.assertThrows(UnsupportedOperationException.class, () -> {
			inTest.getAttribute("any");
		});
	}

}
