package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.CiphertextDirectory;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.common.Constants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;
import java.util.stream.Stream;

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
	private final DirectoryStreamComponent.Factory directoryStreamFactory = mock(DirectoryStreamComponent.Factory.class);

	private final DirectoryStreamFactory inTest = new DirectoryStreamFactory(cryptoPathMapper, directoryStreamFactory);

	@SuppressWarnings("unchecked")

	@BeforeEach
	public void setup() throws IOException {
		when(directoryStreamFactory.create(any(),any(),any(),any(),any())).thenReturn(directoryStreamComp);
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

	@DisplayName("CiphertextDirStream only contains files with names at least 26 chars long and ending with .c9r or .c9s")
	@ParameterizedTest
	@MethodSource("provideFilterExamples")
	public void testCiphertextDirStreamFilter(String fileName, boolean expected) {
		Path p = Mockito.mock(Path.class);
		Mockito.when(p.getFileName()).thenReturn(p);
		Mockito.when(p.toString()).thenReturn(fileName);

		boolean actual = inTest.matchesEncryptedContentPattern(p);

		Assertions.assertEquals(expected, actual);
	}

	private static Stream<Arguments> provideFilterExamples() {
		return Stream.of( //
				Arguments.of("b".repeat(Constants.MIN_CIPHER_NAME_LENGTH - 5)+".c9r", false), //
				Arguments.of("b".repeat(Constants.MIN_CIPHER_NAME_LENGTH - 5)+".c9s", false), //
				Arguments.of("a".repeat(Constants.MIN_CIPHER_NAME_LENGTH - 4)+".c9r", true), //
				Arguments.of("a".repeat(Constants.MIN_CIPHER_NAME_LENGTH - 4)+".c9s", true));
	}

}
