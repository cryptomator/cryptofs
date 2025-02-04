package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;

import static org.mockito.Mockito.mock;

public class OpenCryptoFilesTest {
	private final OpenCryptoFileComponent.Factory openCryptoFileComponentFactory = mock(OpenCryptoFileComponent.Factory.class);
	private final OpenCryptoFile file = mock(OpenCryptoFile.class, "file");
	private final FileChannel ciphertextFileChannel = Mockito.mock(FileChannel.class);
	private final CryptoPath cleartextPath = Mockito.mock(CryptoPath.class, "clear/text.txt");
	@TempDir
	Path tmpDir;

	private OpenCryptoFiles inTest;

	@BeforeEach
	public void setup() throws IOException, ReflectiveOperationException {
		OpenCryptoFileComponent subComponent = mock(OpenCryptoFileComponent.class);
		Mockito.when(subComponent.openCryptoFile()).thenReturn(file);

		Mockito.when(openCryptoFileComponentFactory.create(Mockito.any(), Mockito.any())).thenReturn(subComponent);
		Mockito.when(file.newFileChannel(Mockito.any())).thenReturn(ciphertextFileChannel);

		inTest = new OpenCryptoFiles(openCryptoFileComponentFactory);
	}

	@Test
	public void testGetOrCreate() {
		OpenCryptoFileComponent subComponent1 = mock(OpenCryptoFileComponent.class);
		OpenCryptoFile file1 = mock(OpenCryptoFile.class);
		Mockito.when(subComponent1.openCryptoFile()).thenReturn(file1);

		OpenCryptoFileComponent subComponent2 = mock(OpenCryptoFileComponent.class);
		OpenCryptoFile file2 = mock(OpenCryptoFile.class);
		Mockito.when(subComponent2.openCryptoFile()).thenReturn(file2);

		Mockito.when(openCryptoFileComponentFactory.create(Mockito.any(), Mockito.any())).thenReturn(subComponent1, subComponent2);

		Path p1 = tmpDir.resolve("/foo");
		Path p2 = tmpDir.resolve("/bar");

		Assertions.assertSame(file1, inTest.getOrCreate(cleartextPath, p1));
		Assertions.assertSame(file1, inTest.getOrCreate(cleartextPath, p1));
		Assertions.assertSame(file2, inTest.getOrCreate(cleartextPath, p2));
		Assertions.assertNotSame(file1, file2);
	}

	@Test
	public void testWriteCiphertextFile() throws IOException {
		Path path = tmpDir.resolve("/foo");
		EffectiveOpenOptions openOptions = Mockito.mock(EffectiveOpenOptions.class);
		ByteBuffer contents = StandardCharsets.UTF_8.encode("hello world");

		inTest.writeCiphertextFile(cleartextPath, path, openOptions, contents);

		Mockito.verify(ciphertextFileChannel).write(contents);
	}

	@Test
	public void testReadCiphertextFile() throws IOException {
		byte[] contents = "hello world".getBytes(StandardCharsets.UTF_8);
		Path path = tmpDir.resolve("/foo");
		EffectiveOpenOptions openOptions = Mockito.mock(EffectiveOpenOptions.class);
		Mockito.when(ciphertextFileChannel.size()).thenReturn((long) contents.length);
		Mockito.when(ciphertextFileChannel.read(Mockito.any(ByteBuffer.class))).thenAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			buf.put(contents);
			return contents.length;
		});

		ByteBuffer bytesRead = inTest.readCiphertextFile(cleartextPath, path, openOptions, 1337);

		Assertions.assertEquals("hello world", StandardCharsets.UTF_8.decode(bytesRead).toString());
	}

	@Test
	public void testTwoPhaseMoveFailsWhenTargetIsOpened() throws IOException {
		Path src = tmpDir.resolve("/src").toAbsolutePath();
		Path dst = tmpDir.resolve("/dst").toAbsolutePath();
		CryptoPath cleartextDst = Mockito.mock(CryptoPath.class, "/target/file.txt");
		inTest.getOrCreate(cleartextPath, dst);

		Assertions.assertThrows(FileAlreadyExistsException.class, () -> {
			inTest.prepareMove(src, cleartextDst, dst);
		});
	}

	@Test
	public void testTwoPhaseMoveDoesntChangeAnythingWhenRolledBack() throws IOException {
		Path src = tmpDir.resolve("/src");
		Path dst = tmpDir.resolve("/dst");
		CryptoPath cleartextDst = Mockito.mock(CryptoPath.class, "/target/file.txt");
		inTest.getOrCreate(cleartextPath, src);

		Assertions.assertTrue(inTest.get(src).isPresent());
		Assertions.assertFalse(inTest.get(dst).isPresent());
		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, cleartextDst, dst)) {
			twoPhaseMove.rollback();
		}
		Assertions.assertTrue(inTest.get(src).isPresent());
		Assertions.assertFalse(inTest.get(dst).isPresent());
	}

	@Test
	public void testTwoPhaseMoveChangesReferencesWhenCommitted() throws IOException {
		Path src = tmpDir.resolve("/src").toAbsolutePath();
		Path dst = tmpDir.resolve("/dst").toAbsolutePath();
		CryptoPath cleartextDst = Mockito.mock(CryptoPath.class, "/target/file.txt");
		inTest.getOrCreate(cleartextPath, src);

		Assertions.assertTrue(inTest.get(src).isPresent());
		Assertions.assertFalse(inTest.get(dst).isPresent());
		OpenCryptoFile srcFile = inTest.get(src).get();
		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, cleartextDst, dst)) {
			twoPhaseMove.commit();
		}
		Assertions.assertFalse(inTest.get(src).isPresent());
		Assertions.assertTrue(inTest.get(dst).isPresent());
		OpenCryptoFile dstFile = inTest.get(dst).get();
		Assertions.assertSame(srcFile, dstFile);
		Mockito.verify(dstFile).updateCurrentFilePath(Mockito.argThat(ps -> ps.ciphertextPath().equals(dst) && ps.cleartextPath().equals(cleartextDst)));
	}

	@Test
	public void testCloseClosesRemainingOpenFiles() {
		Path path1 = Mockito.mock(Path.class, "/file1");
		ClearAndCipherPath paths1 = new ClearAndCipherPath(cleartextPath, path1);
		Mockito.when(path1.toAbsolutePath()).thenReturn(path1);
		Mockito.when(path1.normalize()).thenReturn(path1);
		OpenCryptoFileComponent subComponent1 = mock(OpenCryptoFileComponent.class);
		OpenCryptoFile file1 = mock(OpenCryptoFile.class, "file1");
		Mockito.doReturn(subComponent1).when(openCryptoFileComponentFactory).create(Mockito.argThat(ps -> ps.ciphertextPath().equals(path1)), Mockito.any());
		Mockito.when(subComponent1.openCryptoFile()).thenReturn(file1);
		Mockito.when(file1.getCurrentFilePaths()).thenReturn(paths1);

		Path path2 = Mockito.mock(Path.class, "/file2");
		ClearAndCipherPath paths2 = new ClearAndCipherPath(cleartextPath, path2);
		Mockito.when(path2.toAbsolutePath()).thenReturn(path2);
		Mockito.when(path2.normalize()).thenReturn(path2);
		OpenCryptoFileComponent subComponent2 = mock(OpenCryptoFileComponent.class);
		OpenCryptoFile file2 = mock(OpenCryptoFile.class, "file2");
		Mockito.doReturn(subComponent2).when(openCryptoFileComponentFactory).create(Mockito.argThat(ps -> ps.ciphertextPath().equals(path2)), Mockito.any());
		Mockito.when(subComponent2.openCryptoFile()).thenReturn(file2);
		Mockito.when(file2.getCurrentFilePaths()).thenReturn(paths2);

		Assertions.assertEquals(file1, inTest.getOrCreate(cleartextPath, path1));
		Assertions.assertEquals(file2, inTest.getOrCreate(cleartextPath, path2));
		Assertions.assertEquals(file1, inTest.get(path1).get());
		Assertions.assertEquals(file2, inTest.get(path2).get());
		inTest.close();

		Mockito.verify(file1).close();
		Mockito.verify(file2).close();
		Assertions.assertFalse(inTest.get(path1).isPresent());
		Assertions.assertFalse(inTest.get(path2).isPresent());
	}

}
