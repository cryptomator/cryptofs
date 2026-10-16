package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CiphertextFilePath;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.Symlinks;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
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

	private final Cryptor cryptor = mock(Cryptor.class);
	private final FileNameCryptor fileNameCryptor = mock(FileNameCryptor.class);
	private final FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private final FileContentCryptor fileContentCryptor = mock(FileContentCryptor.class);
	private final CiphertextFilePath ciphertextPath = mock(CiphertextFilePath.class);
	private final Path ciphertextRawPath = mock(Path.class);
	private final FileSystem fileSystem = mock(FileSystem.class);
	private final FileSystemProvider provider = mock(FileSystemProvider.class);
	private final UserDefinedFileAttributeView delegate = mock(UserDefinedFileAttributeView.class);
	private final CryptoPath cleartextPath = mock(CryptoPath.class);
	private final CryptoPathMapper pathMapper = mock(CryptoPathMapper.class);
	private final Symlinks symlinks = mock(Symlinks.class);

	private CryptoUserDefinedFileAttributeView inTest;

	@BeforeEach
	public void setUp() throws IOException {
		when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenAnswer(invocation -> invocation.getArgument(1));
		when(fileNameCryptor.decryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenAnswer(invocation -> invocation.getArgument(1));
		when(fileHeaderCryptor.headerSize()).thenReturn(4);
		when(fileHeaderCryptor.decryptHeader(Mockito.any())).thenReturn(Mockito.mock(FileHeader.class));
		when(fileHeaderCryptor.encryptHeader(Mockito.any())).thenReturn(StandardCharsets.UTF_8.encode("HEAD"));
		when(fileContentCryptor.ciphertextChunkSize()).thenReturn(1024);
		when(fileContentCryptor.cleartextChunkSize()).thenReturn(1024);
		when(fileContentCryptor.cleartextSize(Mockito.anyLong())).thenCallRealMethod();
		when(fileContentCryptor.decryptChunk(Mockito.any(), Mockito.anyLong(), Mockito.any(), Mockito.anyBoolean())).thenAnswer(invocation -> invocation.getArgument(0));
		when(fileContentCryptor.encryptChunk(Mockito.any(), Mockito.anyLong(), Mockito.any())).thenAnswer(invocation -> invocation.getArgument(0));

		when(ciphertextRawPath.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		when(provider.getFileAttributeView(ciphertextRawPath, UserDefinedFileAttributeView.class)).thenReturn(delegate);
		when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.FILE);
		when(pathMapper.getCiphertextFilePath(cleartextPath)).thenReturn(ciphertextPath);
		when(ciphertextPath.getFilePath()).thenReturn(ciphertextRawPath);

		inTest = new CryptoUserDefinedFileAttributeView(cleartextPath, pathMapper, new LinkOption[]{}, symlinks, cryptor);
	}

	@Test
	public void testName() {
		Assertions.assertEquals("user", inTest.name());
	}

	@Test
	public void testList() throws IOException {
		when(delegate.list()).thenReturn(Arrays.asList("c9r.Foo", "c9r.Bar"));
		List<String> result = inTest.list();
		MatcherAssert.assertThat(result, CoreMatchers.hasItems("Foo", "Bar"));
	}

	@Test
	public void testSize() throws IOException {
		when(delegate.size("c9r.Foo")).thenReturn(50);
		int result = inTest.size("Foo");
		Assertions.assertEquals(46, result);
	}

	@Test
	public void testWrite() throws IOException {
		when(delegate.write(Mockito.eq("c9r.Foo"), Mockito.any())).thenAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(1);
			int len = buf.remaining();
			buf.position(buf.position() + len);
			return len;
		});

		int written = inTest.write("Foo", StandardCharsets.UTF_8.encode("Hello World"));
		Assertions.assertEquals("Hello World".length(), written);
		Mockito.verify(delegate).write(Mockito.eq("c9r.Foo"), Mockito.any());
	}

	@Test
	public void testRead() throws IOException {
		byte[] content = "HEADHello World".getBytes(StandardCharsets.UTF_8);
		when(delegate.size("c9r.Foo")).thenReturn(content.length);
		when(delegate.read(Mockito.eq("c9r.Foo"), Mockito.any())).thenAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(1);
			buf.put(content);
			return content.length;
		});

		ByteBuffer buf = ByteBuffer.allocate(inTest.size("Foo"));
		int read = inTest.read("Foo", buf);
		Assertions.assertEquals("Hello World".length(), read);
		buf.flip();
		Assertions.assertEquals("Hello World", StandardCharsets.UTF_8.decode(buf).toString());
	}

	@Test
	public void testDelete() throws IOException {
		inTest.delete("Foo");
		Mockito.verify(delegate).delete(Mockito.eq("c9r.Foo"));

	}

}