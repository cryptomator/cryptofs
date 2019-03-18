package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.cryptomator.cryptolib.api.Cryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DirectoryStreamFactoryTest {

	private final FileSystem fileSystem = mock(FileSystem.class);
	private final FileSystemProvider provider = mock(FileSystemProvider.class);
	private final FinallyUtil finallyUtil = mock(FinallyUtil.class);
	private final Cryptor cryptor = mock(Cryptor.class);
	private final LongFileNameProvider longFileNameProvider = mock(LongFileNameProvider.class);
	private final ConflictResolver conflictResolver = mock(ConflictResolver.class);
	private final CryptoPathMapper cryptoPathMapper = mock(CryptoPathMapper.class);
	private final EncryptedNamePattern encryptedNamePattern = new EncryptedNamePattern();

	private final DirectoryStreamFactory inTest = new DirectoryStreamFactory(cryptor, longFileNameProvider, conflictResolver, cryptoPathMapper, finallyUtil, encryptedNamePattern);

	@SuppressWarnings("unchecked")

	@BeforeEach
	public void setup() {
		doAnswer(invocation -> {
			for (Object runnable : invocation.getArguments()) {
				((RunnableThrowingException<?>) runnable).run();
			}
			return null;
		}).when(finallyUtil).guaranteeInvocationOf(any(RunnableThrowingException.class), any(RunnableThrowingException.class), any(RunnableThrowingException.class));
		doAnswer(invocation -> {
			Iterator<RunnableThrowingException<?>> iterator = invocation.getArgument(0);
			while (iterator.hasNext()) {
				iterator.next().run();
			}
			return null;
		}).when(finallyUtil).guaranteeInvocationOf(any(Iterator.class));
		when(fileSystem.provider()).thenReturn(provider);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testNewDirectoryStreamCreatesDirectoryStream() throws IOException {
		CryptoPath path = mock(CryptoPath.class);
		Filter<? super Path> filter = mock(Filter.class);
		String dirId = "dirIdAbc";
		Path dirPath = mock(Path.class);
		when(dirPath.getFileSystem()).thenReturn(fileSystem);
		when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory(dirId, dirPath));

		DirectoryStream<Path> directoryStream = inTest.newDirectoryStream(path, filter);

		assertNotNull(directoryStream);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testCloseClosesAllNonClosedDirectoryStreams() throws IOException {
		Filter<? super Path> filter = mock(Filter.class);
		CryptoPath pathA = mock(CryptoPath.class);
		CryptoPath pathB = mock(CryptoPath.class);
		Path dirPathA = mock(Path.class);
		when(dirPathA.getFileSystem()).thenReturn(fileSystem);
		Path dirPathB = mock(Path.class);
		when(dirPathB.getFileSystem()).thenReturn(fileSystem);
		when(cryptoPathMapper.getCiphertextDir(pathA)).thenReturn(new CiphertextDirectory("dirIdA", dirPathA));
		when(cryptoPathMapper.getCiphertextDir(pathB)).thenReturn(new CiphertextDirectory("dirIdB", dirPathB));
		DirectoryStream<Path> streamA = mock(DirectoryStream.class);
		DirectoryStream<Path> streamB = mock(DirectoryStream.class);
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
		String dirId = "dirIdAbc";
		Path dirPath = mock(Path.class);
		when(dirPath.getFileSystem()).thenReturn(fileSystem);
		when(cryptoPathMapper.getCiphertextDir(path)).thenReturn(new CiphertextDirectory(dirId, dirPath));
		when(provider.newDirectoryStream(same(dirPath), any())).thenReturn(mock(DirectoryStream.class));

		inTest.close();
		Assertions.assertThrows(ClosedFileSystemException.class, () -> {
			inTest.newDirectoryStream(path, filter);
		});
	}

}
