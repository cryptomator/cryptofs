package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.Symlinks;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CryptoUserDefinedFileAttributeViewTest {

	private Cryptor cryptor = mock(Cryptor.class);
	private FileNameCryptor fileNameCryptor = mock(FileNameCryptor.class);
	private Path ciphertextPath = mock(Path.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private FileSystemProvider provider = mock(FileSystemProvider.class);
	private UserDefinedFileAttributeView delegate = mock(UserDefinedFileAttributeView.class);
	private CryptoPath cleartextPath = mock(CryptoPath.class);
	private CryptoPathMapper pathMapper = mock(CryptoPathMapper.class);
	private Symlinks symlinks = mock(Symlinks.class);
	private OpenCryptoFiles openCryptoFiles = mock(OpenCryptoFiles.class);

	private CryptoUserDefinedFileAttributeView inTest;

	@BeforeEach
	public void setUp() throws IOException {
		when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenAnswer(invocation -> invocation.getArgument(1));
		when(fileNameCryptor.decryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenAnswer(invocation -> invocation.getArgument(1));
		when(ciphertextPath.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		when(provider.getFileAttributeView(ciphertextPath, UserDefinedFileAttributeView.class)).thenReturn(delegate);
		when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CryptoPathMapper.CiphertextFileType.FILE);
		when(pathMapper.getCiphertextFilePath(cleartextPath, CryptoPathMapper.CiphertextFileType.FILE)).thenReturn(ciphertextPath);

		inTest = new CryptoUserDefinedFileAttributeView(cryptor, cleartextPath, pathMapper, new LinkOption[]{}, symlinks, openCryptoFiles);
	}

	@Test
	public void testName() {
		Assertions.assertEquals("user", inTest.name());
	}

	@Test
	public void testList() throws IOException {
		when(delegate.list()).thenReturn(Arrays.asList("user.cryptomator.Foo", "user.cryptomator.Bar"));
		List<String> result = inTest.list();
		MatcherAssert.assertThat(result, CoreMatchers.hasItems("Foo", "Bar"));
	}

	@Test
	public void testSize() throws IOException {
		when(delegate.size("user.cryptomator.Foo")).thenReturn(50);
		int result = inTest.size("Foo");
		Assertions.assertEquals(50, result);
	}

	@Test
	public void testWrite() throws IOException {
		when(delegate.write(Mockito.eq("user.cryptomator.Foo"), Mockito.any())).thenAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(1);
			int len = buf.remaining();
			buf.position(buf.position() + len);
			return len;
		});

		byte[] content = "Hello World".getBytes(StandardCharsets.UTF_8);
		int result = inTest.write("Foo", ByteBuffer.wrap(content));
		Mockito.verify(delegate).write(Mockito.eq("user.cryptomator.Foo"), Mockito.any());
		Assertions.assertEquals(content.length, result);
	}

	@Test
	public void testRead() throws IOException {
		byte[] content = "Hello World".getBytes(StandardCharsets.UTF_8);
		when(delegate.size("user.cryptomator.Foo")).thenReturn(content.length);
		when(delegate.read(Mockito.eq("user.cryptomator.Foo"), Mockito.any())).thenAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(1);
			buf.put(content);
			return content.length;
		});

		ByteBuffer buf = ByteBuffer.allocate(inTest.size("Foo"));
		int result = inTest.read("Foo", buf);
		Assertions.assertEquals(content.length, result);
		Assertions.assertArrayEquals(content, buf.array());
	}

	@Test
	public void testDelete() throws IOException {
		inTest.delete("Foo");
		Mockito.verify(delegate).delete(Mockito.eq("user.cryptomator.Foo"));

	}

}
