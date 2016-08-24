package org.cryptomator.cryptofs;

import java.nio.file.FileStore;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class CryptoFileStoreTest {

	@Test
	public void testSupportsFileAttributeView1() {
		FileStore delegate = Mockito.mock(FileStore.class);
		Mockito.when(delegate.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
		Mockito.when(delegate.supportsFileAttributeView(FileOwnerAttributeView.class)).thenReturn(true);
		Mockito.when(delegate.supportsFileAttributeView(BasicFileAttributeView.class)).thenReturn(true);
		Mockito.when(delegate.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(false);

		CryptoFileStore fileStore = new CryptoFileStore(delegate);
		Assert.assertTrue(fileStore.supportsFileAttributeView(PosixFileAttributeView.class));
		Assert.assertTrue(fileStore.supportsFileAttributeView(FileOwnerAttributeView.class));
		Assert.assertTrue(fileStore.supportsFileAttributeView(BasicFileAttributeView.class));
		Assert.assertFalse(fileStore.supportsFileAttributeView(DosFileAttributeView.class));
	}

	@Test
	public void testSupportsFileAttributeView2() {
		FileStore delegate = Mockito.mock(FileStore.class);
		Mockito.when(delegate.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
		Mockito.when(delegate.supportsFileAttributeView(FileOwnerAttributeView.class)).thenReturn(true);
		Mockito.when(delegate.supportsFileAttributeView(BasicFileAttributeView.class)).thenReturn(true);
		Mockito.when(delegate.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(false);

		CryptoFileStore fileStore = new CryptoFileStore(delegate);
		Assert.assertTrue(fileStore.supportsFileAttributeView("posix"));
		Assert.assertTrue(fileStore.supportsFileAttributeView("owner"));
		Assert.assertTrue(fileStore.supportsFileAttributeView("basic"));
		Assert.assertFalse(fileStore.supportsFileAttributeView("dos"));
	}

}
