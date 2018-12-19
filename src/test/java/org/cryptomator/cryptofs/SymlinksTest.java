package org.cryptomator.cryptofs;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.spi.AbstractInterruptibleChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

public class SymlinksTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private final CryptoPathMapper cryptoPathMapper = Mockito.mock(CryptoPathMapper.class);
	private final OpenCryptoFiles openCryptoFiles = Mockito.mock(OpenCryptoFiles.class);
	private final ReadonlyFlag readonlyFlag = Mockito.mock(ReadonlyFlag.class);

	private final CryptoPath cleartextPath = Mockito.mock(CryptoPath.class, "cleartextPath");
	private final OpenCryptoFile ciphertextFile = Mockito.mock(OpenCryptoFile.class);
	private final Path ciphertextPath = Mockito.mock(Path.class, "ciphertextPath");
	private final FileChannel ciphertextFileChannel = Mockito.mock(FileChannel.class);

	private Symlinks inTest;

	@Before
	public void setup() throws ReflectiveOperationException, IOException {
		inTest = new Symlinks(cryptoPathMapper, openCryptoFiles, readonlyFlag);

		Mockito.when(openCryptoFiles.getOrCreate(Mockito.eq(ciphertextPath), Mockito.any())).thenReturn(ciphertextFile);
		Mockito.when(ciphertextFile.newFileChannel(Mockito.any())).thenReturn(ciphertextFileChannel);
		Field closeLockField = AbstractInterruptibleChannel.class.getDeclaredField("closeLock");
		closeLockField.setAccessible(true);
		closeLockField.set(ciphertextFileChannel, new Object());
	}

	@Test
	public void testCreateSymbolicLink() throws IOException {
		Path target = Mockito.mock(Path.class, "targetPath");
		Mockito.doNothing().when(cryptoPathMapper).assertNonExisting(cleartextPath);
		Mockito.when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CryptoPathMapper.CiphertextFileType.SYMLINK)).thenReturn(ciphertextPath);
		Mockito.when(target.toString()).thenReturn("/symlink/target/path");

		inTest.createSymbolicLink(cleartextPath, target, null);

		ArgumentCaptor<ByteBuffer> bytesWritten = ArgumentCaptor.forClass(ByteBuffer.class);
		Mockito.verify(ciphertextFileChannel).write(bytesWritten.capture());
		Assert.assertEquals("/symlink/target/path", StandardCharsets.UTF_8.decode(bytesWritten.getValue()).toString());
	}

	@Test
	public void testReadSymbolicLink() throws IOException {
		String targetPath = "/symlink/target/path2";
		byte[] fileContent = targetPath.getBytes(StandardCharsets.UTF_8);
		CryptoPath resolvedTargetPath = Mockito.mock(CryptoPath.class, "resolvedTargetPath");
		Mockito.when(cryptoPathMapper.getCiphertextFilePath(cleartextPath, CryptoPathMapper.CiphertextFileType.SYMLINK)).thenReturn(ciphertextPath);
		Mockito.when(ciphertextFileChannel.size()).thenReturn((long) fileContent.length);
		Mockito.when(ciphertextFileChannel.read(Mockito.any(ByteBuffer.class))).thenAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			buf.put(fileContent);
			return fileContent.length;
		});
		Mockito.when(cleartextPath.resolveSibling(targetPath)).thenReturn(resolvedTargetPath);

		CryptoPath read = inTest.readSymbolicLink(cleartextPath);

		Assert.assertSame(resolvedTargetPath, read);
	}

}
