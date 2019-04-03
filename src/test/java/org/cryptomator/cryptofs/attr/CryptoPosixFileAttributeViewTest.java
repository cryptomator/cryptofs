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
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.spi.FileSystemProvider;
import java.util.HashSet;
import java.util.Set;

import static java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE;
import static java.util.Arrays.asList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CryptoPosixFileAttributeViewTest {

	private Path linkCiphertextPath = mock(Path.class);
	private Path ciphertextPath = mock(Path.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private FileSystemProvider provider = mock(FileSystemProvider.class);
	private PosixFileAttributeView delegate = mock(PosixFileAttributeView.class);
	private PosixFileAttributeView linkDelegate = mock(PosixFileAttributeView.class);

	private CryptoPath link = Mockito.mock(CryptoPath.class);
	private CryptoPath cleartextPath = mock(CryptoPath.class);
	private CryptoPathMapper pathMapper = mock(CryptoPathMapper.class);
	private Symlinks symlinks = mock(Symlinks.class);
	private OpenCryptoFiles openCryptoFiles = mock(OpenCryptoFiles.class);
	private AttributeProvider fileAttributeProvider = mock(AttributeProvider.class);
	private ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);

	private CryptoPosixFileAttributeView inTest;

	@BeforeEach
	public void setUp() throws IOException {
		when(linkCiphertextPath.getFileSystem()).thenReturn(fileSystem);
		when(ciphertextPath.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		when(provider.getFileAttributeView(ciphertextPath, PosixFileAttributeView.class)).thenReturn(delegate);
		when(provider.getFileAttributeView(ciphertextPath, BasicFileAttributeView.class)).thenReturn(delegate);
		when(provider.getFileAttributeView(linkCiphertextPath, PosixFileAttributeView.class)).thenReturn(linkDelegate);

		when(symlinks.resolveRecursively(link)).thenReturn(cleartextPath);
		when(pathMapper.getCiphertextFileType(link)).thenReturn(CryptoPathMapper.CiphertextFileType.SYMLINK);
		when(pathMapper.getCiphertextFilePath(link, CryptoPathMapper.CiphertextFileType.SYMLINK)).thenReturn(linkCiphertextPath);
		when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CryptoPathMapper.CiphertextFileType.FILE);
		when(pathMapper.getCiphertextFilePath(cleartextPath, CryptoPathMapper.CiphertextFileType.FILE)).thenReturn(ciphertextPath);

		inTest = new CryptoPosixFileAttributeView(cleartextPath, pathMapper, new LinkOption[]{}, symlinks, openCryptoFiles, fileAttributeProvider, readonlyFlag);
	}

	@Test
	public void testNameReturnsPosix() {
		Assertions.assertEquals("posix", inTest.name());
	}

	@Test
	public void testGetOwnerDelegatesToDelegate() throws IOException {
		UserPrincipal expectedPrincipal = mock(UserPrincipal.class);
		when(delegate.getOwner()).thenReturn(expectedPrincipal);

		UserPrincipal result = inTest.getOwner();

		Assertions.assertSame(expectedPrincipal, result);
	}

	@Test
	public void testSetOwnerDelegatesToDelegate() throws IOException {
		UserPrincipal expectedPrincipal = mock(UserPrincipal.class);

		inTest.setOwner(expectedPrincipal);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setOwner(expectedPrincipal);
	}

	@Test
	public void testSetPermissionsDelegatesToDelegate() throws IOException {
		Set<PosixFilePermission> expectedPermissions = new HashSet<>(asList(OTHERS_WRITE));

		inTest.setPermissions(expectedPermissions);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setPermissions(expectedPermissions);
	}

	@Test
	public void testSetGroupDelegatesToDelegate() throws IOException {
		GroupPrincipal expectedPricipal = mock(GroupPrincipal.class);

		inTest.setGroup(expectedPricipal);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setGroup(expectedPricipal);
	}

	@Test
	public void testReadAttributesUsesProvider() throws IOException {
		PosixFileAttributes expectedAttributes = mock(PosixFileAttributes.class);
		when(fileAttributeProvider.readAttributes(cleartextPath, PosixFileAttributes.class)).thenReturn(expectedAttributes);

		PosixFileAttributes result = inTest.readAttributes();

		Assertions.assertSame(expectedAttributes, result);
	}

	@Test
	public void testSetTimesDelegatesToDelegate() throws IOException {
		FileTime lastModifiedTime = FileTime.fromMillis(39293923);
		FileTime lastAccessTime = FileTime.fromMillis(39293924);
		FileTime createTime = FileTime.fromMillis(39293925);

		inTest.setTimes(lastModifiedTime, lastAccessTime, createTime);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setTimes(lastModifiedTime, lastAccessTime, createTime);
	}

	@Test
	public void testSetPermissionsOfSymlinkNoFollow() throws IOException {
		Set<PosixFilePermission> expectedPermissions = new HashSet<>(asList(OTHERS_WRITE));

		PosixFileAttributeView view = new CryptoPosixFileAttributeView(link, pathMapper, new LinkOption[]{LinkOption.NOFOLLOW_LINKS}, symlinks, openCryptoFiles, fileAttributeProvider, readonlyFlag);
		view.setPermissions(expectedPermissions);

		verify(linkDelegate).setPermissions(expectedPermissions);
	}

	@Test
	public void testSetPermissionsOfSymlinkFollow() throws IOException {
		Set<PosixFilePermission> expectedPermissions = new HashSet<>(asList(OTHERS_WRITE));

		PosixFileAttributeView view = new CryptoPosixFileAttributeView(link, pathMapper, new LinkOption[]{}, symlinks, openCryptoFiles, fileAttributeProvider, readonlyFlag);
		view.setPermissions(expectedPermissions);

		verify(delegate).setPermissions(expectedPermissions);
	}

}
