package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.cryptomator.cryptofs.ReadonlyFlag;
import org.cryptomator.cryptofs.Symlinks;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.spi.FileSystemProvider;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CryptoFileOwnerAttributeViewTest {

	private Path linkCiphertextPath = mock(Path.class);
	private Path ciphertextPath = mock(Path.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private FileSystemProvider provider = mock(FileSystemProvider.class);
	private FileOwnerAttributeView delegate = mock(FileOwnerAttributeView.class);
	private FileOwnerAttributeView linkDelegate = mock(FileOwnerAttributeView.class);

	private CryptoPath link = Mockito.mock(CryptoPath.class);
	private CryptoPath cleartextPath = mock(CryptoPath.class);
	private CryptoPathMapper pathMapper = mock(CryptoPathMapper.class);
	private Symlinks symlinks = mock(Symlinks.class);
	private OpenCryptoFiles openCryptoFiles = mock(OpenCryptoFiles.class);
	private ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);

	private CryptoFileOwnerAttributeView inTest;

	@BeforeEach
	public void setup() throws IOException {
		when(linkCiphertextPath.getFileSystem()).thenReturn(fileSystem);
		when(ciphertextPath.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		when(provider.getFileAttributeView(ciphertextPath, FileOwnerAttributeView.class)).thenReturn(delegate);
		when(provider.getFileAttributeView(linkCiphertextPath, FileOwnerAttributeView.class)).thenReturn(linkDelegate);

		when(symlinks.resolveRecursively(link)).thenReturn(cleartextPath);
		when(pathMapper.getCiphertextFileType(link)).thenReturn(CryptoPathMapper.CiphertextFileType.SYMLINK);
		when(pathMapper.getCiphertextFilePath(link, CryptoPathMapper.CiphertextFileType.SYMLINK)).thenReturn(linkCiphertextPath);
		when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CryptoPathMapper.CiphertextFileType.FILE);
		when(pathMapper.getCiphertextFilePath(cleartextPath, CryptoPathMapper.CiphertextFileType.FILE)).thenReturn(ciphertextPath);

		inTest = new CryptoFileOwnerAttributeView(cleartextPath, pathMapper, new LinkOption[]{}, symlinks, openCryptoFiles, readonlyFlag);
	}

	@Test
	public void testNameReturnsOwner() {
		Assertions.assertEquals("owner", inTest.name());
	}

	@Test
	public void testGetOwnerDelegates() throws IOException {
		UserPrincipal principal = mock(UserPrincipal.class);
		when(delegate.getOwner()).thenReturn(principal);

		Assertions.assertSame(principal, inTest.getOwner());
	}

	@Test
	public void testSetOwnerDelegates() throws IOException {
		UserPrincipal principal = mock(UserPrincipal.class);

		inTest.setOwner(principal);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setOwner(principal);
	}

	@Test
	public void testSetOwnerOfSymlinkNoFollow() throws IOException {
		UserPrincipal principal = mock(UserPrincipal.class);

		CryptoFileOwnerAttributeView view = new CryptoFileOwnerAttributeView(link, pathMapper, new LinkOption[]{LinkOption.NOFOLLOW_LINKS}, symlinks, openCryptoFiles, readonlyFlag);
		view.setOwner(principal);

		verify(linkDelegate).setOwner(principal);
	}

	@Test
	public void testSetOwnerOfSymlinkFollow() throws IOException {
		UserPrincipal principal = mock(UserPrincipal.class);

		CryptoFileOwnerAttributeView view = new CryptoFileOwnerAttributeView(link, pathMapper, new LinkOption[]{}, symlinks, openCryptoFiles, readonlyFlag);
		view.setOwner(principal);

		verify(delegate).setOwner(principal);
	}

}
