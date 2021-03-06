package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CiphertextFilePath;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.cryptomator.cryptofs.ReadonlyFlag;
import org.cryptomator.cryptofs.Symlinks;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.spi.FileSystemProvider;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CryptoDosFileAttributeViewTest {

	private CiphertextFilePath linkCiphertextPath = mock(CiphertextFilePath.class);
	private CiphertextFilePath ciphertextPath = mock(CiphertextFilePath.class);
	private Path linkCiphertextRawPath = mock(Path.class);
	private Path ciphertextRawPath = mock(Path.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private FileSystemProvider provider = mock(FileSystemProvider.class);
	private DosFileAttributeView delegate = mock(DosFileAttributeView.class);
	private DosFileAttributeView linkDelegate = mock(DosFileAttributeView.class);

	private CryptoPath link = Mockito.mock(CryptoPath.class);
	private CryptoPath cleartextPath = mock(CryptoPath.class);
	private CryptoPathMapper pathMapper = mock(CryptoPathMapper.class);
	private Symlinks symlinks = mock(Symlinks.class);
	private OpenCryptoFiles openCryptoFiles = mock(OpenCryptoFiles.class);
	private AttributeProvider fileAttributeProvider = mock(AttributeProvider.class);
	private ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);

	private CryptoDosFileAttributeView inTest;

	@BeforeEach
	public void setup() throws IOException {
		when(linkCiphertextRawPath.getFileSystem()).thenReturn(fileSystem);

		when(ciphertextRawPath.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		when(provider.getFileAttributeView(ciphertextRawPath, DosFileAttributeView.class)).thenReturn(delegate);
		when(provider.getFileAttributeView(ciphertextRawPath, BasicFileAttributeView.class)).thenReturn(delegate);
		when(provider.getFileAttributeView(linkCiphertextRawPath, DosFileAttributeView.class)).thenReturn(linkDelegate);

		when(symlinks.resolveRecursively(link)).thenReturn(cleartextPath);
		when(pathMapper.getCiphertextFileType(link)).thenReturn(CiphertextFileType.SYMLINK);
		when(pathMapper.getCiphertextFilePath(link)).thenReturn(linkCiphertextPath);
		when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.FILE);
		when(pathMapper.getCiphertextFilePath(cleartextPath)).thenReturn(ciphertextPath);

		when(linkCiphertextPath.getSymlinkFilePath()).thenReturn(linkCiphertextRawPath);
		when(ciphertextPath.getFilePath()).thenReturn(ciphertextRawPath);

		inTest = new CryptoDosFileAttributeView(cleartextPath, pathMapper, new LinkOption[]{}, symlinks, openCryptoFiles, fileAttributeProvider, readonlyFlag);
	}

	@Test
	public void testNameIsDos() {
		Assertions.assertEquals("dos", inTest.name());
	}

	@ParameterizedTest
	@CsvSource({"true", "false"})
	public void testSetReadOnly(boolean value) throws IOException {
		inTest.setReadOnly(value);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setReadOnly(value);
	}

	@ParameterizedTest
	@CsvSource({"true", "false"})
	public void testSetHidden(boolean value) throws IOException {
		inTest.setHidden(value);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setHidden(value);
	}

	@ParameterizedTest
	@CsvSource({"true", "false"})
	public void testSetSystem(boolean value) throws IOException {
		inTest.setSystem(value);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setSystem(value);
	}

	@ParameterizedTest
	@CsvSource({"true", "false"})
	public void testSetArchive(boolean value) throws IOException {
		inTest.setArchive(value);

		verify(readonlyFlag).assertWritable();
		verify(delegate).setArchive(value);
	}

	@ParameterizedTest
	@CsvSource({"true", "false"})
	public void testSetHiddenOfSymlinkNoFollow(boolean value) throws IOException {
		CryptoDosFileAttributeView view = new CryptoDosFileAttributeView(link, pathMapper, new LinkOption[]{LinkOption.NOFOLLOW_LINKS}, symlinks, openCryptoFiles, fileAttributeProvider, readonlyFlag);
		view.setHidden(value);

		verify(linkDelegate).setHidden(value);
	}

	@ParameterizedTest
	@CsvSource({"true", "false"})
	public void testSetHiddenOfSymlinkFollow(boolean value) throws IOException {
		CryptoDosFileAttributeView view = new CryptoDosFileAttributeView(link, pathMapper, new LinkOption[]{}, symlinks, openCryptoFiles, fileAttributeProvider, readonlyFlag);
		view.setHidden(value);

		verify(delegate).setHidden(value);
	}

}
