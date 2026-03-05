package org.cryptomator.cryptofs.fh;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.ReadonlyFlag;
import org.cryptomator.cryptofs.ch.ChannelComponent;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
import org.cryptomator.cryptofs.inuse.FileAlreadyInUseException;
import org.cryptomator.cryptofs.inuse.InUseManager;
import org.cryptomator.cryptofs.inuse.UseToken;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OpenCryptoFileTest {

	private static FileSystem FS;
	private static AtomicReference<Path> CURRENT_FILE_PATH;
	private static AtomicReference<CryptoPath> CURRENT_CLEARTEXT_FILE_PATH;
	private ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);
	private FileCloseListener closeListener = mock(FileCloseListener.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private FileHeaderHolder headerHolder = mock(FileHeaderHolder.class);
	private ChunkIO chunkIO = mock(ChunkIO.class);
	private AtomicLong fileSize = Mockito.mock(AtomicLong.class);
	private AtomicReference<Instant> lastModified = new AtomicReference(Instant.ofEpochMilli(0));
	private OpenCryptoFileComponent openCryptoFileComponent = mock(OpenCryptoFileComponent.class);
	private ChannelComponent.Factory channelComponentFactory = mock(ChannelComponent.Factory.class);
	private ChannelComponent channelComponent = mock(ChannelComponent.class);
	private InUseManager inUseManager = mock(InUseManager.class);
	private UseToken useToken = spy(UseToken.INIT_TOKEN); //sealed class, hence we spy on existing token

	@BeforeAll
	public static void setup() {
		FS = Jimfs.newFileSystem("OpenCryptoFileTest", Configuration.unix().toBuilder().setAttributeViews("basic", "posix").build());
		CURRENT_CLEARTEXT_FILE_PATH = new AtomicReference<>(Mockito.mock(CryptoPath.class, "/clear/text/path"));
		CURRENT_FILE_PATH = new AtomicReference<>(FS.getPath("currentFile"));
	}

	@AfterAll
	public static void tearDown() throws IOException {
		FS.close();
	}

	@BeforeEach
	public void beforeEach() {
		when(useToken.isClosed()).thenReturn(false);
	}

	OpenCryptoFile getTestInstance(String filename) {
		var p = FS.getPath(filename);
		if (Files.exists(p)) {
			throw new RuntimeException("Path " + p + "already exists.");
		}
		CURRENT_FILE_PATH.set(p);
		return new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, CURRENT_FILE_PATH, fileSize, CURRENT_CLEARTEXT_FILE_PATH, lastModified, openCryptoFileComponent, inUseManager, useToken);
	}

	@Test
	@DisplayName("on close(), trigger closeListener and delete lockFile")
	public void testClose() {
		var openCryptoFile = getTestInstance("testClose");
		var expectedCiphertextPath = CURRENT_FILE_PATH.get();

		openCryptoFile.close();
		verify(closeListener).close(expectedCiphertextPath, openCryptoFile);
		verify(useToken).close();
	}

	// tests https://github.com/cryptomator/cryptofs/issues/51
	@Test
	@DisplayName("if the first file channel fails to open, call OpenCryptoFile::close")
	public void testFailedFirstFileChannelImmediatelyCallsClose() {
		UncheckedIOException expectedException = new UncheckedIOException(new IOException("fail!"));
		EffectiveOpenOptions options = Mockito.mock(EffectiveOpenOptions.class);
		Mockito.when(options.createOpenOptionsForEncryptedFile()).thenThrow(expectedException);
		var openCryptoFile = spy(getTestInstance("testClose"));

		UncheckedIOException exception = Assertions.assertThrows(UncheckedIOException.class, () -> {
			openCryptoFile.newFileChannel(options);
		});
		Assertions.assertSame(expectedException, exception);
		verify(openCryptoFile).close();
	}

	@Test
	@DisplayName("if useToken is not closed, don't reassign it")
	public void testNewFileChannelOpenUseToken() throws IOException {
		var openCryptoFile = spy(getTestInstance("testNewFileChannelOpenUseToken"));
		var expectedCiphertextPath = CURRENT_FILE_PATH.get();

		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), readonlyFlag);
		var cleartextChannel = mock(CleartextFileChannel.class);
		Mockito.when(headerHolder.get()).thenReturn(Mockito.mock(FileHeader.class));
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		Mockito.when(fileHeaderCryptor.headerSize()).thenReturn(42);
		Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		Mockito.when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		Mockito.when(channelComponent.channel()).thenReturn(cleartextChannel);
		when(useToken.isClosed()).thenReturn(false);

		openCryptoFile.newFileChannel(options);

		verify(inUseManager, never()).use(expectedCiphertextPath);
	}

	@Test
	@DisplayName("if the file is openend only for reading, don't check usage")
	public void testIgnoreUsageForReadonly() throws IOException {
		var openCryptoFile = spy(getTestInstance("testNewFileChannelIgnoreUsage"));
		var expectedCiphertextPath = CURRENT_FILE_PATH.get();
		Files.createFile(expectedCiphertextPath);

		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.READ), readonlyFlag);
		var cleartextChannel = mock(CleartextFileChannel.class);
		Mockito.when(headerHolder.get()).thenReturn(Mockito.mock(FileHeader.class));
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		Mockito.when(fileHeaderCryptor.headerSize()).thenReturn(42);
		Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		Mockito.when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		Mockito.when(channelComponent.channel()).thenReturn(cleartextChannel);
		when(useToken.isClosed()).thenReturn(true);

		openCryptoFile.newFileChannel(options);

		verify(inUseManager, never()).use(expectedCiphertextPath);
	}

	@Test
	@DisplayName("if useToken is closed, get a new one")
	public void testNewFileChannelClosedToken() throws IOException {
		var openCryptoFile = spy(getTestInstance("testNewFileChannelClosedUseToken"));
		var expectedCiphertextPath = CURRENT_FILE_PATH.get();

		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), readonlyFlag);
		var cleartextChannel = mock(CleartextFileChannel.class);
		Mockito.when(headerHolder.get()).thenReturn(Mockito.mock(FileHeader.class));
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		Mockito.when(fileHeaderCryptor.headerSize()).thenReturn(42);
		Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		Mockito.when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		Mockito.when(channelComponent.channel()).thenReturn(cleartextChannel);
		when(useToken.isClosed()).thenReturn(true);
		when(inUseManager.use(expectedCiphertextPath)).thenReturn(useToken);

		openCryptoFile.newFileChannel(options);

		verify(inUseManager).use(expectedCiphertextPath);
	}

	@Test
	@DisplayName("if the file is in use and file is opened for writing, throw exception")
	public void testInUseFileThrowsException() throws IOException {
		var openCryptoFile = spy(getTestInstance("testInUseFileThrowsException"));
		var expectedCiphertextPath = CURRENT_FILE_PATH.get();

		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.WRITE), readonlyFlag);
		when(useToken.isClosed()).thenReturn(true);
		when(inUseManager.use(expectedCiphertextPath)).thenThrow(FileAlreadyInUseException.class);

		Assertions.assertThrows(FileAlreadyInUseException.class, () -> {
			openCryptoFile.newFileChannel(options);
		});
	}

	@Test
	@DisplayName("if the second file channel fails to open, do nothing")
	public void testFailedSecondFileChannelDoesNothing() throws IOException {
		var openCryptoFile = spy(getTestInstance("testFailedSecondFileChannelDoesNothing"));

		UncheckedIOException expectedException = new UncheckedIOException(new IOException("fail!"));
		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), readonlyFlag);
		var cleartextChannel = mock(CleartextFileChannel.class);
		Mockito.when(headerHolder.get()).thenReturn(Mockito.mock(FileHeader.class));
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		Mockito.when(fileHeaderCryptor.headerSize()).thenReturn(42);
		Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		Mockito.when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		Mockito.when(channelComponent.channel()).thenReturn(cleartextChannel);

		EffectiveOpenOptions failingOptions = Mockito.mock(EffectiveOpenOptions.class);
		Mockito.when(failingOptions.createOpenOptionsForEncryptedFile()).thenThrow(expectedException);

		try (var channel = openCryptoFile.newFileChannel(options)) {
			UncheckedIOException exception = Assertions.assertThrows(UncheckedIOException.class, () -> {
				openCryptoFile.newFileChannel(failingOptions);
			});
			Assertions.assertSame(expectedException, exception);
			verify(openCryptoFile, never()).close();
		}
	}

	@Test
	@DisplayName("Opening a file channel with TRUNCATE_EXISTING calls truncate(0) on the cleartextChannel")
	public void testCleartextChannelTruncateCalledOnTruncateExisting() throws IOException {
		var openCryptoFile = spy(getTestInstance("testCleartextChannelTruncateCalled"));

		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING), readonlyFlag);
		var cleartextChannel = mock(CleartextFileChannel.class);
		Mockito.when(headerHolder.get()).thenReturn(Mockito.mock(FileHeader.class));
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		Mockito.when(fileHeaderCryptor.headerSize()).thenReturn(42);
		Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		Mockito.when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		Mockito.when(channelComponent.channel()).thenReturn(cleartextChannel);

		openCryptoFile.newFileChannel(options);
		verify(cleartextChannel).truncate(0L);
	}

	@Test
	@DisplayName("Updating the current file path moves the inUse file")
	public void testUpdateCurrentPath() {
		var currentPath = mock(Path.class, "current Path");
		var newPath = mock(Path.class, "new Path");
		var currentPathWrapper = new AtomicReference<>(currentPath);
		OpenCryptoFile openCryptoFile = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, currentPathWrapper, fileSize, CURRENT_CLEARTEXT_FILE_PATH, lastModified, openCryptoFileComponent, inUseManager, useToken);
		doNothing().when(useToken).moveTo(newPath);

		openCryptoFile.updateCurrentFilePath(newPath);
		verify(useToken).moveTo(newPath);
	}

	@Test
	@DisplayName("Updating the current file path with null closes in-use-file")
	public void testUpdateCurrentPathWithNull() {
		var currentPath = mock(Path.class, "current Path");
		var currentPathWrapper = new AtomicReference<>(currentPath);
		OpenCryptoFile openCryptoFile = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, currentPathWrapper, fileSize, CURRENT_CLEARTEXT_FILE_PATH, lastModified, openCryptoFileComponent, inUseManager, useToken);
		doNothing().when(useToken).close();

		openCryptoFile.updateCurrentFilePath(null);
		verify(useToken).close();
	}


	@Nested
	@DisplayName("Testing ::initFileHeader")
	public class InitFilHeaderTests {

		EffectiveOpenOptions options = Mockito.mock(EffectiveOpenOptions.class);
		FileChannel cipherFileChannel = Mockito.mock(FileChannel.class, "cipherFilechannel");
		OpenCryptoFile inTest = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, CURRENT_FILE_PATH, fileSize, CURRENT_CLEARTEXT_FILE_PATH, lastModified, openCryptoFileComponent, inUseManager);

		@Test
		@DisplayName("Skip file header init, if the file header already exists in memory")
		public void testInitFileHeaderExisting() throws IOException {
			var header = Mockito.mock(FileHeader.class);
			Mockito.when(headerHolder.get()).thenReturn(header);

			inTest.initFileHeader(options, cipherFileChannel);

			Mockito.verify(headerHolder, never()).loadExisting(any());
			Mockito.verify(headerHolder, never()).createNew();
		}

		@Test
		@DisplayName("Load file header from file, if not present and neither create nor create_new set")
		public void testInitFileHeaderLoad() throws IOException {
			Mockito.when(headerHolder.get()).thenThrow(new IllegalStateException("no Header set"));
			Mockito.when(options.createNew()).thenReturn(false);
			Mockito.when(options.create()).thenReturn(false);

			inTest.initFileHeader(options, cipherFileChannel);

			Mockito.verify(headerHolder, times(1)).loadExisting(cipherFileChannel);
			Mockito.verify(headerHolder, never()).createNew();
		}

		@Test
		@DisplayName("Create new file header, if not present and create_new set")
		public void testInitFileHeaderCreateNew() throws IOException {
			Mockito.when(headerHolder.get()).thenThrow(new IllegalStateException("no Header set"));
			Mockito.when(options.createNew()).thenReturn(true);

			inTest.initFileHeader(options, cipherFileChannel);

			Mockito.verify(headerHolder, times(1)).createNew();
			Mockito.verify(headerHolder, never()).loadExisting(any());
		}

		@Test
		@DisplayName("Create new file header, if not present, create set and channel.size() == 0")
		public void testInitFileHeaderCreateAndSize0() throws IOException {
			Mockito.when(headerHolder.get()).thenThrow(new IllegalStateException("no Header set"));
			Mockito.when(options.createNew()).thenReturn(false);
			Mockito.when(options.create()).thenReturn(true);
			Mockito.when(cipherFileChannel.size()).thenReturn(0L);

			inTest.initFileHeader(options, cipherFileChannel);

			Mockito.verify(headerHolder, times(1)).createNew();
			Mockito.verify(headerHolder, never()).loadExisting(any());
		}

		@Test
		@DisplayName("Load file header, if create is set but channel has size > 0")
		public void testInitFileHeaderCreateAndSizeGreater0() throws IOException {
			Mockito.when(headerHolder.get()).thenThrow(new IllegalStateException("no Header set"));
			Mockito.when(options.createNew()).thenReturn(false);
			Mockito.when(options.create()).thenReturn(true);
			Mockito.when(cipherFileChannel.size()).thenReturn(42L);

			inTest.initFileHeader(options, cipherFileChannel);

			Mockito.verify(headerHolder, times(1)).loadExisting(cipherFileChannel);
			Mockito.verify(headerHolder, never()).createNew();
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	@DisplayName("FileChannels")
	public class FileChannelFactoryTest {

		private final AtomicLong realFileSize = new AtomicLong(-1L);
		private OpenCryptoFile openCryptoFile;
		private CleartextFileChannel cleartextFileChannel;
		private AtomicReference<Consumer<FileChannel>> listener;
		private AtomicReference<FileChannel> ciphertextChannel;

		@BeforeAll
		public void setup() throws IOException {
			FS = Jimfs.newFileSystem("OpenCryptoFileTest.FileChannelFactoryTest", Configuration.unix().toBuilder().setAttributeViews("basic", "posix").build());
			CURRENT_FILE_PATH = new AtomicReference<>(FS.getPath("currentFile"));
			openCryptoFile = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, CURRENT_FILE_PATH, realFileSize, CURRENT_CLEARTEXT_FILE_PATH, lastModified, openCryptoFileComponent, inUseManager);
			cleartextFileChannel = mock(CleartextFileChannel.class);
			listener = new AtomicReference<>();
			ciphertextChannel = new AtomicReference<>();

			Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
			Mockito.when(channelComponentFactory.create(Mockito.any(), Mockito.any(), Mockito.any())).thenAnswer(invocation -> {
				ciphertextChannel.set(invocation.getArgument(0));
				listener.set(invocation.getArgument(2));
				return channelComponent;
			});
			Mockito.when(channelComponent.channel()).thenReturn(cleartextFileChannel);
		}

		@Test
		@Order(0)
		@DisplayName("getting size fails before creating first file channel")
		public void testGetSizeBeforeCreatingFileChannel() {
			Assertions.assertFalse(openCryptoFile.size().isPresent());
		}

		@Test
		@Order(10)
		@DisplayName("create first FileChannel")
		public void createFileChannel() throws IOException {
			var expectedCiphertextPath = CURRENT_FILE_PATH.get();
			var attrs = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-x---"));
			EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), readonlyFlag);
			when(inUseManager.use(expectedCiphertextPath)).thenReturn(useToken);
			FileChannel ch = openCryptoFile.newFileChannel(options, attrs);
			Assertions.assertSame(cleartextFileChannel, ch);
			verify(chunkIO).registerChannel(ciphertextChannel.get(), true);
			verify(inUseManager).use(expectedCiphertextPath);
		}

		@Test
		@Order(11)
		@DisplayName("getting size succeeds after creating first file channel")
		public void testGetSizeAfterCreatingFirstFileChannel() {
			Assertions.assertEquals(0l, openCryptoFile.size().get());
		}

		// related to https://github.com/cryptomator/cryptofs/issues/51
		@Test
		@Order(12)
		@DisplayName("create second FileChannel with invalid options (which must not close the OpenCryptoFile)")
		public void errorDuringCreationOfSecondChannel() {
			UncheckedIOException expectedException = new UncheckedIOException(new IOException("fail!"));
			EffectiveOpenOptions options = Mockito.mock(EffectiveOpenOptions.class);
			Mockito.when(options.createOpenOptionsForEncryptedFile()).thenThrow(expectedException);

			UncheckedIOException exception = Assertions.assertThrows(UncheckedIOException.class, () -> {
				openCryptoFile.newFileChannel(options);
			});
			Assertions.assertSame(expectedException, exception);
			verify(closeListener, Mockito.never()).close(CURRENT_FILE_PATH.get(), openCryptoFile);
		}

		@Test
		@Order(13)
		@DisplayName("getting size succeeds after creating second file channel")
		public void testGetSizeAfterCreatingSecondFileChannel() {
			Assertions.assertEquals(0l, openCryptoFile.size().get());
		}

		@Test
		@Order(100)
		@DisplayName("closeListener triggers chunkIO.unregisterChannel()")
		public void triggerCloseListener() throws IOException {
			Assumptions.assumeTrue(listener.get() != null);
			Assumptions.assumeTrue(ciphertextChannel.get() != null);

			listener.get().accept(ciphertextChannel.get());
			verify(chunkIO).unregisterChannel(ciphertextChannel.get());
		}

	}

}
