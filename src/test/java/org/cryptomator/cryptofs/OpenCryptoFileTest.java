package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.UncheckedThrows.allowUncheckedThrowsOf;
import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;
import java.util.Random;
import java.util.Set;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class OpenCryptoFileTest {

	private static final int HEADER_SIZE = 23;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	private Cryptor cryptor = mock(Cryptor.class);
	private FileHeaderCryptor headerCryptor = mock(FileHeaderCryptor.class);
	private FileContentCryptor contentCryptor = mock(FileContentCryptor.class);
	private FileHeader createdHeader = mock(FileHeader.class);
	private FileHeader decryptedHeader = mock(FileHeader.class);

	private EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
	@SuppressWarnings("unchecked")
	private Set<OpenOption> openOptionsForEncryptedFile = mock(Set.class);

	private Path path = mock(Path.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private FileSystemProvider fileSystemProvider = mock(FileSystemProvider.class);
	private FileChannel channel = spy(FileChannel.class);

	private Runnable onClosed = mock(Runnable.class);

	@Before
	public void setUp() throws IOException {
		when(cryptor.fileContentCryptor()).thenReturn(contentCryptor);
		when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);

		when(headerCryptor.headerSize()).thenReturn(HEADER_SIZE);
		when(headerCryptor.create()).thenReturn(createdHeader);
		when(headerCryptor.decryptHeader(any())).thenReturn(decryptedHeader);

		when(options.createOpenOptionsForEncryptedFile()).thenReturn(openOptionsForEncryptedFile);

		when(path.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(fileSystemProvider);
		when(fileSystemProvider.newFileChannel(any(), any())).thenReturn(channel);
	}

	@Test
	public void testConstructionOpensChannelUsingOpenOptions() throws IOException {
		createOpenCryptoFile();

		verify(fileSystemProvider).newFileChannel(path, openOptionsForEncryptedFile);
	}

	@Test
	public void testConstructionCreatesHeaderIfTruncatedExistingFile() throws IOException {
		when(options.truncateExisting()).thenReturn(true);
		createOpenCryptoFile();

		verify(headerCryptor).create();
	}

	@Test
	public void testConstructionCreatesHeaderIfCreateNewFlagIsPresent() throws IOException {
		when(options.createNew()).thenReturn(true);
		createOpenCryptoFile();

		verify(headerCryptor).create();
	}

	@Test
	public void testConstructionCreatesHeaderIfCreateFlagIsPresentAndChannelIsEmpty() throws IOException {
		when(options.create()).thenReturn(true);
		when(channel.size()).thenReturn(0L);
		createOpenCryptoFile();

		verify(headerCryptor).create();
	}

	@Test
	public void testConstructionReadsHeaderIfCreateFlagIsPresentAndChannelIsNotEmpty() throws IOException {
		when(options.create()).thenReturn(true);
		when(channel.size()).thenReturn((long) HEADER_SIZE);
		byte[] headerData = randomData(HEADER_SIZE);
		when(channel.read(any(ByteBuffer.class))).thenAnswer(invocation -> {
			invocation.getArgumentAt(0, ByteBuffer.class).put(headerData);
			return headerData.length;
		});
		createOpenCryptoFile();

		verify(headerCryptor).decryptHeader(argThat(contains(headerData)));
	}

	@Test
	public void testConstructionReadsHeaderIfExistingFileWasOpened() throws IOException {
		byte[] headerData = randomData(HEADER_SIZE);
		when(channel.read(any(ByteBuffer.class))).thenAnswer(invocation -> {
			invocation.getArgumentAt(0, ByteBuffer.class).put(headerData);
			return headerData.length;
		});
		createOpenCryptoFile();

		verify(headerCryptor).decryptHeader(argThat(contains(headerData)));
	}

	@Test
	public void testSizeAfterConstructionWithNewHeaderIsSizeFromHeader() throws IOException {
		long sizeFromHeader = 43L;
		when(createdHeader.getFilesize()).thenReturn(sizeFromHeader);
		when(options.createNew()).thenReturn(true);
		OpenCryptoFile inTest = createOpenCryptoFile();

		assertThat(inTest.size(), is(sizeFromHeader));
	}

	@Test
	public void testSizeAfterConstructionWithLoadedHeaderIsSizeFromHeader() throws IOException {
		long sizeFromHeader = 43L;
		when(decryptedHeader.getFilesize()).thenReturn(sizeFromHeader);
		OpenCryptoFile inTest = createOpenCryptoFile();

		assertThat(inTest.size(), is(sizeFromHeader));
	}

	@Test
	public void testContinuedPartialReadsToAtMostMaxCachedChunksDoNotCauseReadingOrWriting() {
		// TODO
	}

	@Test
	public void testContinuedPartialWritesToAtMostMaxCachedChunksDoNotCauseReadingOrWriting() {
		// TODO
	}

	@Test
	public void testFullChunkWriteDoesNotCauseReadingFromOrWritingToChannel() {
		// TODO
	}

	@Test
	public void testReadOfNonChachedChunkAfterReadingMaxCachedChunksCausesWriting() {
		// TODO
	}

	@Test
	public void testWriteOfNonChachedChunkAfterReadingMaxCachedChunksCausesWriting() {
		// TODO
	}

	@Test
	public void testWriteOfNonChachedChunkAfterWritingMaxCachedChunksCausesWriting() {
		// TODO
	}

	@Test
	public void testReadOfNonChachedChunkAfterWritingMaxCachedChunksCausesWriting() {
		// TODO
	}

	@Test
	public void testSingleMultiChunkWriteSpanningMoreThanMaxCachedChunksCausesWriting() {
		// TODO
	}

	@Test
	public void testWriteCausesWritingOfChunkAndHeaderIfInSyncMode() {
		// TODO
	}

	@Test
	public void testWriteThrowsIOExceptionsFromChannelIfInSyncMode() {
		// TODO
	}

	@Test
	public void testWriteCausesForceMetadataInSyncMetadataMode() {
		// TODO
	}

	@Test
	public void testForceCausesWritingOfCachedChunksAndHeader() {
		// TODO
	}

	@Test
	public void testCloseCausesWritingOfCachedChunksAndHeader() {
		// TODO
	}

	@Test
	public void testCloseInvokesOnCloseHandler() throws IOException {
		OpenCryptoFile openCryptoFile = createOpenCryptoFile();
		openCryptoFile.open(options);

		openCryptoFile.close(options);
		verify(onClosed).run();
	}

	@Test
	public void testCloseAfterMoreOpenCallsDoesNotInvokeOnCloseHandler() throws IOException {
		OpenCryptoFile openCryptoFile = createOpenCryptoFile();
		openCryptoFile.open(options);
		openCryptoFile.open(options);

		openCryptoFile.close(options);
		verify(onClosed, never()).run();
	}

	@Test
	public void testLastCloseAfterMultipleOpenCallsInvokesOnCloseHandler() throws IOException {
		OpenCryptoFile openCryptoFile = createOpenCryptoFile();
		openCryptoFile.open(options);
		openCryptoFile.open(options);

		openCryptoFile.close(options);
		openCryptoFile.close(options);
		verify(onClosed).run();
	}

	@Test
	public void testCloseWithoutOpenFails() throws IOException {
		OpenCryptoFile openCryptoFile = createOpenCryptoFile();

		thrown.expect(IllegalStateException.class);

		openCryptoFile.close(options);
	}

	@Test
	public void testCloseAfterLessOpenCallsInvokesOnCloseHandlerOnlyOnce() throws IOException {
		OpenCryptoFile openCryptoFile = createOpenCryptoFile();
		openCryptoFile.open(options);
		openCryptoFile.open(options);
		openCryptoFile.close(options);

		openCryptoFile.close(options);
		verify(onClosed).run();
	}

	private OpenCryptoFile createOpenCryptoFile() throws IOException {
		return allowUncheckedThrowsOf(IOException.class).from(() -> new OpenCryptoFile(path, options, cryptor, new OpenCounter(), new CryptoFileChannelFactory(), onClosed));
	}

	@Test
	public void testForceMetadata() {
		// TODO
	}

	private byte[] randomData(int size) {
		byte[] result = new byte[size];
		new Random().nextBytes(result);
		return result;
	}

}
