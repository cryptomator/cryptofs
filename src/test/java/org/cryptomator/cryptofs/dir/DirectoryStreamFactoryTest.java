package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DirectoryStreamFactoryTest {

	private final FileSystem fileSystem = mock(FileSystem.class, "fs");
	private final FileSystemProvider provider = mock(FileSystemProvider.class, "provider");
	private final CryptoPathMapper cryptoPathMapper = mock(CryptoPathMapper.class);
	private final DirectoryStreamComponent directoryStreamComp = mock(DirectoryStreamComponent.class);
	private final DirectoryStreamComponent.Builder directoryStreamBuilder = mock(DirectoryStreamComponent.Builder.class);

	private final DirectoryStreamFactory inTest = new DirectoryStreamFactory(cryptoPathMapper, directoryStreamBuilder);

	@SuppressWarnings("unchecked")

	@BeforeEach
	public void setup() throws IOException {
		when(directoryStreamBuilder.cleartextPath(Mockito.any())).thenReturn(directoryStreamBuilder);
		when(directoryStreamBuilder.dirId(Mockito.any())).thenReturn(directoryStreamBuilder);
		when(directoryStreamBuilder.ciphertextDirectoryStream(Mockito.any())).thenReturn(directoryStreamBuilder);
		when(directoryStreamBuilder.filter(Mockito.any())).thenReturn(directoryStreamBuilder);
		when(directoryStreamBuilder.onClose(Mockito.any())).thenReturn(directoryStreamBuilder);
		when(directoryStreamBuilder.build()).thenReturn(directoryStreamComp);
		when(directoryStreamComp.directoryStream()).then(invocation -> mock(CryptoDirectoryStream.class));
		when(fileSystem.provider()).thenReturn(provider);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testNewDirectoryStreamCreatesDirectoryStream() throws IOException {
		CryptoPath path = mock(CryptoPath.class);
		Filter<? super Path> filter = mock(Filter.class);
		String dirId = "dirIdAbc";
		Path dirPath = mock(Path.class, "dirAbc");
		when(dirPath.getFileSystem()).thenReturn(fileSystem);
		when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory(dirId, dirPath));
		DirectoryStream<Path> stream = mock(DirectoryStream.class);
		when(provider.newDirectoryStream(same(dirPath), any())).thenReturn(stream);

		DirectoryStream<Path> directoryStream = inTest.newDirectoryStream(path, filter);

		assertNotNull(directoryStream);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testCloseClosesAllNonClosedDirectoryStreams() throws IOException {
		Filter<? super Path> filter = mock(Filter.class);
		CryptoPath pathA = mock(CryptoPath.class, "pathA");
		CryptoPath pathB = mock(CryptoPath.class, "pathB");
		Path dirPathA = mock(Path.class, "dirPathA");
		when(dirPathA.getFileSystem()).thenReturn(fileSystem);
		Path dirPathB = mock(Path.class, "dirPathB");
		when(dirPathB.getFileSystem()).thenReturn(fileSystem);
		when(cryptoPathMapper.getCiphertextDir(pathA)).thenReturn(new CiphertextDirectory("dirIdA", dirPathA));
		when(cryptoPathMapper.getCiphertextDir(pathB)).thenReturn(new CiphertextDirectory("dirIdB", dirPathB));
		DirectoryStream<Path> streamA = mock(DirectoryStream.class, "streamA");
		DirectoryStream<Path> streamB = mock(DirectoryStream.class, "streamB");
		when(provider.newDirectoryStream(same(dirPathA), any())).thenReturn(streamA);
		when(provider.newDirectoryStream(same(dirPathB), any())).thenReturn(streamB);

		inTest.newDirectoryStream(pathA, filter);
		inTest.newDirectoryStream(pathB, filter);

		inTest.close();

		verify(streamA).close();
		verify(streamB).close();
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testNewDirectoryStreamAfterClosedThrowsClosedFileSystemException() throws IOException {
		CryptoPath path = mock(CryptoPath.class);
		Filter<? super Path> filter = mock(Filter.class);
		
		inTest.close();
		
		Assertions.assertThrows(ClosedFileSystemException.class, () -> {
			inTest.newDirectoryStream(path, filter);
		});
	}

}
