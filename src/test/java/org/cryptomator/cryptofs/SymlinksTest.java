package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemLoopException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;

public class SymlinksTest {

	private final CryptoPathMapper cryptoPathMapper = Mockito.mock(CryptoPathMapper.class);
	private final LongFileNameProvider longFileNameProvider = Mockito.mock(LongFileNameProvider.class);
	private final OpenCryptoFiles openCryptoFiles = Mockito.mock(OpenCryptoFiles.class);
	private final ReadonlyFlag readonlyFlag = Mockito.mock(ReadonlyFlag.class);
	private final FileSystem underlyingFs = Mockito.mock(FileSystem.class);
	private final FileSystemProvider underlyingFsProvider = Mockito.mock(FileSystemProvider.class);

	private Symlinks inTest;

	@BeforeEach
	public void setup() throws IOException {
		inTest = new Symlinks(cryptoPathMapper, longFileNameProvider, openCryptoFiles, readonlyFlag);

		Mockito.when(underlyingFs.provider()).thenReturn(underlyingFsProvider);
	}

	private Path mockExistingSymlink(CryptoPath cleartextPath) throws IOException {
		Path ciphertextRawPath = Mockito.mock(Path.class);
		Path symlinkFilePath = Mockito.mock(Path.class);
		BasicFileAttributes ciphertextPathAttr = Mockito.mock(BasicFileAttributes.class);
		BasicFileAttributes symlinkFilePathAttr = Mockito.mock(BasicFileAttributes.class);
		CiphertextFilePath ciphertextPath = Mockito.mock(CiphertextFilePath.class);
		Mockito.when(ciphertextRawPath.resolve("symlink.c9r")).thenReturn(symlinkFilePath);
		Mockito.when(symlinkFilePath.getParent()).thenReturn(ciphertextRawPath);
		Mockito.when(ciphertextRawPath.getFileSystem()).thenReturn(underlyingFs);
		Mockito.when(symlinkFilePath.getFileSystem()).thenReturn(underlyingFs);
		Mockito.when(underlyingFsProvider.readAttributes(ciphertextRawPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(ciphertextPathAttr);
		Mockito.when(underlyingFsProvider.readAttributes(symlinkFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(symlinkFilePathAttr);
		Mockito.when(ciphertextPathAttr.isDirectory()).thenReturn(true);
		Mockito.when(symlinkFilePathAttr.isRegularFile()).thenReturn(true);
		Mockito.when(cryptoPathMapper.getCiphertextFilePath(cleartextPath)).thenReturn(ciphertextPath);
		Mockito.when(ciphertextPath.getRawPath()).thenReturn(ciphertextRawPath);
		Mockito.when(ciphertextPath.getSymlinkFilePath()).thenReturn(symlinkFilePath);
		return ciphertextRawPath;
	}

	@Test
	public void testCreateSymbolicLink() throws IOException {
		CryptoPath cleartextPath = Mockito.mock(CryptoPath.class);
		Path target = Mockito.mock(Path.class, "targetPath");
		Path ciphertextPath = mockExistingSymlink(cleartextPath);
		Path symlinkFilePath = ciphertextPath.resolve("symlink.c9r");
		Mockito.doNothing().when(cryptoPathMapper).assertNonExisting(cleartextPath);
		Mockito.when(target.toString()).thenReturn("/symlink/target/path");

		inTest.createSymbolicLink(cleartextPath, target);

		ArgumentCaptor<ByteBuffer> bytesWritten = ArgumentCaptor.forClass(ByteBuffer.class);
		Mockito.verify(underlyingFsProvider).createDirectory(Mockito.eq(ciphertextPath), Mockito.any());
		Mockito.verify(openCryptoFiles).writeCiphertextFile(Mockito.eq(symlinkFilePath), Mockito.any(), bytesWritten.capture());
		Assertions.assertEquals("/symlink/target/path", StandardCharsets.UTF_8.decode(bytesWritten.getValue()).toString());
	}

	@Test
	public void testReadSymbolicLink() throws IOException {
		CryptoPath cleartextPath = Mockito.mock(CryptoPath.class);
		CryptoFileSystemImpl cleartextFs = Mockito.mock(CryptoFileSystemImpl.class);
		Mockito.when(cleartextPath.getFileSystem()).thenReturn(cleartextFs);

		String targetPath = "/symlink/target/path2";
		CryptoPath resolvedTargetPath = Mockito.mock(CryptoPath.class, "resolvedTargetPath");
		Path ciphertextPath = mockExistingSymlink(cleartextPath);
		Path symlinkFilePath = ciphertextPath.resolve("symlink.c9r");
		Mockito.when(openCryptoFiles.readCiphertextFile(Mockito.eq(symlinkFilePath), Mockito.any(), Mockito.anyInt())).thenReturn(StandardCharsets.UTF_8.encode(targetPath));

		Mockito.when(cleartextFs.getPath(targetPath)).thenReturn(resolvedTargetPath);

		CryptoPath read = inTest.readSymbolicLink(cleartextPath);

		Assertions.assertSame(resolvedTargetPath, read);
	}

	@Test
	public void testResolveRecursivelyForRegularFile() throws IOException {
		CryptoPath cleartextPath = Mockito.mock(CryptoPath.class);
		Mockito.when(cryptoPathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.FILE);

		CryptoPath resolved = inTest.resolveRecursively(cleartextPath);

		Assertions.assertSame(cleartextPath, resolved);
	}

	@Test
	public void testResolveRecursively() throws IOException {
		CryptoFileSystemImpl cleartextFs = Mockito.mock(CryptoFileSystemImpl.class);
		CryptoPath cleartextPath1 = Mockito.mock(CryptoPath.class);
		CryptoPath cleartextPath2 = Mockito.mock(CryptoPath.class);
		CryptoPath cleartextPath3 = Mockito.mock(CryptoPath.class);
		Path ciphertextPath1 = mockExistingSymlink(cleartextPath1);
		Path ciphertextPath2 = mockExistingSymlink(cleartextPath2);
		Path ciphertextSymlinkPath1 = ciphertextPath1.resolve("symlink.c9r");
		Path ciphertextSymlinkPath2 = ciphertextPath2.resolve("symlink.c9r");
		Mockito.when(cleartextPath1.getFileSystem()).thenReturn(cleartextFs);
		Mockito.when(cleartextPath2.getFileSystem()).thenReturn(cleartextFs);
		Mockito.when(cleartextPath3.getFileSystem()).thenReturn(cleartextFs);
		Mockito.when(cryptoPathMapper.getCiphertextFileType(cleartextPath1)).thenReturn(CiphertextFileType.SYMLINK);
		Mockito.when(cryptoPathMapper.getCiphertextFileType(cleartextPath2)).thenReturn(CiphertextFileType.SYMLINK);
		Mockito.when(cryptoPathMapper.getCiphertextFileType(cleartextPath3)).thenReturn(CiphertextFileType.FILE);
		Mockito.when(openCryptoFiles.readCiphertextFile(Mockito.eq(ciphertextSymlinkPath1), Mockito.any(), Mockito.anyInt())).thenReturn(StandardCharsets.UTF_8.encode("file2"));
		Mockito.when(openCryptoFiles.readCiphertextFile(Mockito.eq(ciphertextSymlinkPath2), Mockito.any(), Mockito.anyInt())).thenReturn(StandardCharsets.UTF_8.encode("file3"));
		Mockito.when(cleartextFs.getPath("file2")).thenReturn(cleartextPath2);
		Mockito.when(cleartextFs.getPath("file3")).thenReturn(cleartextPath3);

		CryptoPath resolved = inTest.resolveRecursively(cleartextPath1);

		Assertions.assertSame(cleartextPath3, resolved);
	}

	@Test
	public void testResolveRecursivelyWithNonExistingTarget() throws IOException {
		CryptoFileSystemImpl cleartextFs = Mockito.mock(CryptoFileSystemImpl.class);
		CryptoPath cleartextPath1 = Mockito.mock(CryptoPath.class);
		CryptoPath cleartextPath2 = Mockito.mock(CryptoPath.class);
		Path ciphertextPath1 = mockExistingSymlink(cleartextPath1);
		Path ciphertextSymlinkPath1 = ciphertextPath1.resolve("symlink.c9r");
		Mockito.when(cleartextPath1.getFileSystem()).thenReturn(cleartextFs);
		Mockito.when(cleartextPath2.getFileSystem()).thenReturn(cleartextFs);
		Mockito.when(cryptoPathMapper.getCiphertextFileType(cleartextPath1)).thenReturn(CiphertextFileType.SYMLINK);
		Mockito.when(cryptoPathMapper.getCiphertextFileType(cleartextPath2)).thenThrow(new NoSuchFileException("cleartextPath2"));
		Mockito.when(openCryptoFiles.readCiphertextFile(Mockito.eq(ciphertextSymlinkPath1), Mockito.any(), Mockito.anyInt())).thenReturn(StandardCharsets.UTF_8.encode("file2"));
		Mockito.when(cleartextFs.getPath("file2")).thenReturn(cleartextPath2);

		CryptoPath resolved = inTest.resolveRecursively(cleartextPath1);

		Assertions.assertSame(cleartextPath2, resolved);
	}

	@Test
	public void testResolveRecursivelyWithLoop() throws IOException {
		CryptoFileSystemImpl cleartextFs = Mockito.mock(CryptoFileSystemImpl.class);
		CryptoPath cleartextPath1 = Mockito.mock(CryptoPath.class);
		CryptoPath cleartextPath2 = Mockito.mock(CryptoPath.class);
		CryptoPath cleartextPath3 = Mockito.mock(CryptoPath.class);
		Path ciphertextPath1 = mockExistingSymlink(cleartextPath1);
		Path ciphertextPath2 = mockExistingSymlink(cleartextPath2);
		Path ciphertextPath3 = mockExistingSymlink(cleartextPath3);
		Path ciphertextSymlinkPath1 = ciphertextPath1.resolve("symlink.c9r");
		Path ciphertextSymlinkPath2 = ciphertextPath2.resolve("symlink.c9r");
		Path ciphertextSymlinkPath3 = ciphertextPath3.resolve("symlink.c9r");
		Mockito.when(cleartextPath1.getFileSystem()).thenReturn(cleartextFs);
		Mockito.when(cleartextPath2.getFileSystem()).thenReturn(cleartextFs);
		Mockito.when(cleartextPath3.getFileSystem()).thenReturn(cleartextFs);
		Mockito.when(cryptoPathMapper.getCiphertextFileType(cleartextPath1)).thenReturn(CiphertextFileType.SYMLINK);
		Mockito.when(cryptoPathMapper.getCiphertextFileType(cleartextPath2)).thenReturn(CiphertextFileType.SYMLINK);
		Mockito.when(cryptoPathMapper.getCiphertextFileType(cleartextPath3)).thenReturn(CiphertextFileType.SYMLINK);
		Mockito.when(openCryptoFiles.readCiphertextFile(Mockito.eq(ciphertextSymlinkPath1), Mockito.any(), Mockito.anyInt())).thenReturn(StandardCharsets.UTF_8.encode("file2"));
		Mockito.when(openCryptoFiles.readCiphertextFile(Mockito.eq(ciphertextSymlinkPath2), Mockito.any(), Mockito.anyInt())).thenReturn(StandardCharsets.UTF_8.encode("file3"));
		Mockito.when(openCryptoFiles.readCiphertextFile(Mockito.eq(ciphertextSymlinkPath3), Mockito.any(), Mockito.anyInt())).thenReturn(StandardCharsets.UTF_8.encode("file1"));
		Mockito.when(cleartextFs.getPath("file2")).thenReturn(cleartextPath2);
		Mockito.when(cleartextFs.getPath("file3")).thenReturn(cleartextPath3);
		Mockito.when(cleartextFs.getPath("file1")).thenReturn(cleartextPath1);

		Assertions.assertThrows(FileSystemLoopException.class, () -> {
			inTest.resolveRecursively(cleartextPath1);
		});
	}

}
