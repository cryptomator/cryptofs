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
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.spi.FileSystemProvider;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
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
	private CiphertextFileKey ciphertextFileKey = new CiphertextFileKey();
	private AtomicLong fileSize = mock(AtomicLong.class);
	private AtomicReference<Instant> lastModified = new AtomicReference(Instant.ofEpochMilli(0));
	private OpenCryptoFileComponent openCryptoFileComponent = mock(OpenCryptoFileComponent.class);
	private ChannelComponent.Factory channelComponentFactory = mock(ChannelComponent.Factory.class);
	private ChannelComponent channelComponent = mock(ChannelComponent.class);
	private InUseManager inUseManager = mock(InUseManager.class);
	private UseToken useToken = spy(UseToken.INIT_TOKEN); //sealed class, hence we spy on existing token

	@BeforeAll
	public static void setup() {
		FS = Jimfs.newFileSystem("OpenCryptoFileTest", Configuration.unix().toBuilder().setAttributeViews("basic", "posix").build());
		CURRENT_CLEARTEXT_FILE_PATH = new AtomicReference<>(mock(CryptoPath.class, "/clear/text/path"));
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
		return new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, ciphertextFileKey, CURRENT_FILE_PATH, fileSize, CURRENT_CLEARTEXT_FILE_PATH, lastModified, openCryptoFileComponent, inUseManager, useToken);
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
		EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
		when(options.createOpenOptionsForEncryptedFile()).thenThrow(expectedException);
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
		var header = mock(FileHeader.class);
		doReturn(header).when(headerHolder).get();
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(fileHeaderCryptor.headerSize()).thenReturn(42);
		when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		when(channelComponent.channel()).thenReturn(cleartextChannel);
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
		var header = mock(FileHeader.class);
		doReturn(header).when(headerHolder).get();
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(fileHeaderCryptor.headerSize()).thenReturn(42);
		when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		when(channelComponent.channel()).thenReturn(cleartextChannel);
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
		var header = mock(FileHeader.class);
		doReturn(header).when(headerHolder).get();
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(fileHeaderCryptor.headerSize()).thenReturn(42);
		when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		when(channelComponent.channel()).thenReturn(cleartextChannel);
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
		var header = mock(FileHeader.class);
		doReturn(header).when(headerHolder).get();
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(fileHeaderCryptor.headerSize()).thenReturn(42);
		when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		when(channelComponent.channel()).thenReturn(cleartextChannel);

		EffectiveOpenOptions failingOptions = mock(EffectiveOpenOptions.class);
		when(failingOptions.createOpenOptionsForEncryptedFile()).thenThrow(expectedException);

		try (var channel = openCryptoFile.newFileChannel(options)) {
			UncheckedIOException exception = Assertions.assertThrows(UncheckedIOException.class, () -> {
				openCryptoFile.newFileChannel(failingOptions);
			});
			Assertions.assertSame(expectedException, exception);
			verify(openCryptoFile, never()).close();
		}
	}

	@Test
	@DisplayName("closing the last channel unregisters the file while holding its monitor")
	public void testLastChannelUnregistersUnderMonitor() throws IOException {
		var openCryptoFile = getTestInstance("testLastChannelUnregistersUnderMonitor");
		var expectedCiphertextPath = CURRENT_FILE_PATH.get();
		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), readonlyFlag);
		when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		var channelCloseListener = new AtomicReference<Consumer<FileChannel>>();
		when(channelComponentFactory.create(any(), any(), any())).thenAnswer(invocation -> {
			channelCloseListener.set(invocation.getArgument(2));
			return channelComponent;
		});
		var cleartextChannel = mock(CleartextFileChannel.class);
		doReturn(cleartextChannel).when(channelComponent).channel();
		var heldMonitor = new AtomicBoolean();
		doAnswer(invocation -> {
			heldMonitor.set(Thread.holdsLock(openCryptoFile));
			return null;
		}).when(closeListener).close(expectedCiphertextPath, openCryptoFile);

		openCryptoFile.newFileChannel(options);
		channelCloseListener.get().accept(null);

		Assertions.assertTrue(heldMonitor.get());
	}

	@Test
	@DisplayName("Opening a file channel with TRUNCATE_EXISTING leaves truncation to the caller")
	public void testCleartextChannelNotTruncatedOnTruncateExisting() throws IOException {
		var openCryptoFile = spy(getTestInstance("testCleartextChannelNotTruncated"));
		Files.write(CURRENT_FILE_PATH.get(), new byte[100]);

		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING), readonlyFlag);
		var cleartextChannel = mock(CleartextFileChannel.class);
		var header = mock(FileHeader.class);
		doReturn(header).when(headerHolder).get();
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(fileHeaderCryptor.headerSize()).thenReturn(42);
		when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		when(channelComponent.channel()).thenReturn(cleartextChannel);

		openCryptoFile.newFileChannel(options);
		verify(cleartextChannel, never()).truncate(anyLong());
		Assertions.assertEquals(100, Files.size(CURRENT_FILE_PATH.get()));
	}

	@Test
	@DisplayName("Updating the current file path moves the inUse file")
	public void testUpdateCurrentPath() {
		var currentPath = mock(Path.class, "current Path");
		var newPath = mock(Path.class, "new Path");
		var currentPathWrapper = new AtomicReference<>(currentPath);
		OpenCryptoFile openCryptoFile = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, ciphertextFileKey, currentPathWrapper, fileSize, CURRENT_CLEARTEXT_FILE_PATH, lastModified, openCryptoFileComponent, inUseManager, useToken);
		doNothing().when(useToken).moveTo(newPath);

		openCryptoFile.updateCurrentFilePath(newPath);
		verify(useToken).moveTo(newPath);
	}

	@Test
	@DisplayName("Updating the current file path with null closes in-use-file")
	public void testUpdateCurrentPathWithNull() {
		var currentPath = mock(Path.class, "current Path");
		var currentPathWrapper = new AtomicReference<>(currentPath);
		OpenCryptoFile openCryptoFile = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, ciphertextFileKey, currentPathWrapper, fileSize, CURRENT_CLEARTEXT_FILE_PATH, lastModified, openCryptoFileComponent, inUseManager, useToken);
		doNothing().when(useToken).close();

		openCryptoFile.updateCurrentFilePath(null);
		verify(useToken).close();
	}


	@Nested
	@DisplayName("Testing ::initFileHeader")
	public class InitFilHeaderTests {

		EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
		FileChannel cipherFileChannel = mock(FileChannel.class, "cipherFilechannel");
		OpenCryptoFile inTest = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, ciphertextFileKey, CURRENT_FILE_PATH, fileSize, CURRENT_CLEARTEXT_FILE_PATH, lastModified, openCryptoFileComponent, inUseManager);

		@Test
		@DisplayName("Skip file header init, if the file header already exists in memory")
		public void testInitFileHeaderExisting() throws IOException {
			var header = mock(FileHeader.class);
			when(headerHolder.get()).thenReturn(header);

			inTest.initFileHeader(options, cipherFileChannel);

			verify(headerHolder, never()).loadExisting(any());
			verify(headerHolder, never()).createNew();
		}

		@Test
		@DisplayName("Load file header from file, if not present and neither create nor create_new set")
		public void testInitFileHeaderLoad() throws IOException {
			when(headerHolder.get()).thenThrow(new IllegalStateException("no Header set"));
			when(options.createNew()).thenReturn(false);
			when(options.create()).thenReturn(false);

			inTest.initFileHeader(options, cipherFileChannel);

			verify(headerHolder, times(1)).loadExisting(cipherFileChannel);
			verify(headerHolder, never()).createNew();
		}

		@Test
		@DisplayName("Create new file header, if not present and create_new set")
		public void testInitFileHeaderCreateNew() throws IOException {
			when(headerHolder.get()).thenThrow(new IllegalStateException("no Header set"));
			when(options.createNew()).thenReturn(true);

			inTest.initFileHeader(options, cipherFileChannel);

			verify(headerHolder, times(1)).createNew();
			verify(headerHolder, never()).loadExisting(any());
		}

		@Test
		@DisplayName("Create new file header, if not present, create set and channel.size() == 0")
		public void testInitFileHeaderCreateAndSize0() throws IOException {
			when(headerHolder.get()).thenThrow(new IllegalStateException("no Header set"));
			when(options.createNew()).thenReturn(false);
			when(options.create()).thenReturn(true);
			when(cipherFileChannel.size()).thenReturn(0L);

			inTest.initFileHeader(options, cipherFileChannel);

			verify(headerHolder, times(1)).createNew();
			verify(headerHolder, never()).loadExisting(any());
		}

		@Test
		@DisplayName("Load file header, if create is set but channel has size > 0")
		public void testInitFileHeaderCreateAndSizeGreater0() throws IOException {
			when(headerHolder.get()).thenThrow(new IllegalStateException("no Header set"));
			when(options.createNew()).thenReturn(false);
			when(options.create()).thenReturn(true);
			when(cipherFileChannel.size()).thenReturn(42L);

			inTest.initFileHeader(options, cipherFileChannel);

			verify(headerHolder, times(1)).loadExisting(cipherFileChannel);
			verify(headerHolder, never()).createNew();
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
			openCryptoFile = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, ciphertextFileKey, CURRENT_FILE_PATH, realFileSize, CURRENT_CLEARTEXT_FILE_PATH, lastModified, openCryptoFileComponent, inUseManager);
			cleartextFileChannel = mock(CleartextFileChannel.class);
			listener = new AtomicReference<>();
			ciphertextChannel = new AtomicReference<>();

			when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
			when(channelComponentFactory.create(any(), any(), any())).thenAnswer(invocation -> {
				ciphertextChannel.set(invocation.getArgument(0));
				listener.set(invocation.getArgument(2));
				return channelComponent;
			});
			when(channelComponent.channel()).thenReturn(cleartextFileChannel);
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
			EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
			when(options.createOpenOptionsForEncryptedFile()).thenThrow(expectedException);

			UncheckedIOException exception = Assertions.assertThrows(UncheckedIOException.class, () -> {
				openCryptoFile.newFileChannel(options);
			});
			Assertions.assertSame(expectedException, exception);
			verify(closeListener, never()).close(CURRENT_FILE_PATH.get(), openCryptoFile);
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

	@Nested
	@DisplayName("detecting a replaced ciphertext file")
	class ReplacementDetection {

		private static final Object FIRST_KEY = "first key";
		private static final Object REPLACEMENT_KEY = "replacement key";
		private static final FileTime FIRST_MODIFIED = FileTime.from(Instant.parse("2020-01-01T00:00:00Z"));

		private final Path path = mock(Path.class, "joinedFile");
		private final FileSystem fileSystem = mock(FileSystem.class);
		private final FileSystemProvider provider = mock(FileSystemProvider.class);
		private final FileChannel firstCiphertextChannel = mock(FileChannel.class, "first");
		private final FileChannel candidate = mock(FileChannel.class, "candidate");
		private final FileHeader header = mock(FileHeader.class);
		private final CleartextFileChannel cleartextChannel = mock(CleartextFileChannel.class);
		private final EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
		private final EffectiveOpenOptions deleteOnCloseOptions = mock(EffectiveOpenOptions.class);
		private final BasicFileAttributes firstAttributes = mock(BasicFileAttributes.class, "first attributes");
		private final BasicFileAttributes replacementAttributes = mock(BasicFileAttributes.class, "replacement attributes");
		private OpenCryptoFile inTest;

		@BeforeEach
		void setup() throws IOException {
			when(path.getFileSystem()).thenReturn(fileSystem);
			when(fileSystem.provider()).thenReturn(provider);
			when(provider.newFileChannel(eq(path), any(), any(FileAttribute[].class))).thenReturn(firstCiphertextChannel, candidate);
			when(headerHolder.get()).thenReturn(header);
			when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
			when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
			when(channelComponent.channel()).thenReturn(cleartextChannel);
			when(deleteOnCloseOptions.deleteOnClose()).thenReturn(true);
			when(firstAttributes.fileKey()).thenReturn(FIRST_KEY);
			when(firstAttributes.lastModifiedTime()).thenReturn(FIRST_MODIFIED);
			when(replacementAttributes.fileKey()).thenReturn(REPLACEMENT_KEY);
			when(headerHolder.isHeaderOf(any())).thenReturn(true);
			inTest = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, ciphertextFileKey, new AtomicReference<>(path), fileSize, new AtomicReference<>(), lastModified, openCryptoFileComponent, inUseManager, useToken);
		}

		private void openFirstChannel() throws IOException {
			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenReturn(FIRST_KEY);
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenReturn(firstAttributes);
				inTest.newFileChannel(options);
			}
		}

		private void assertDetachedAsReplaced() {
			Assertions.assertNull(inTest.getCurrentFilePath());
			verify(closeListener).close(path, inTest);
			verify(useToken).close();
			Assertions.assertThrows(CiphertextReplacedException.class, () -> inTest.newFileChannel(options));
		}

		@Test
		@DisplayName("a channel joining after the ciphertext was replaced detaches the open file without opening the replacement")
		void testKeyMismatchBeforeOpen() throws IOException {
			openFirstChannel();

			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenReturn(REPLACEMENT_KEY);
				var e = Assertions.assertThrows(CiphertextReplacedException.class, () -> inTest.newFileChannel(options));
				Assertions.assertTrue(e.retryable());
			}

			verify(provider, times(1)).newFileChannel(eq(path), any(), any(FileAttribute[].class));
			assertDetachedAsReplaced();
		}

		@Test
		@DisplayName("a channel joining while the ciphertext gets replaced detaches the open file and closes the candidate")
		void testKeyMismatchAfterOpen() throws IOException {
			openFirstChannel();

			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenReturn(FIRST_KEY);
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenReturn(replacementAttributes);
				var e = Assertions.assertThrows(CiphertextReplacedException.class, () -> inTest.newFileChannel(options));
				Assertions.assertTrue(e.retryable());
			}

			verify(candidate).close();
			verify(chunkIO, never()).registerChannel(eq(candidate), anyBoolean());
			assertDetachedAsReplaced();
		}

		@Test
		@DisplayName("a first channel whose ciphertext gets replaced while opening detaches the open file")
		void testFirstChannelKeyRace() throws IOException {
			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenReturn(FIRST_KEY);
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenReturn(replacementAttributes);
				var e = Assertions.assertThrows(CiphertextReplacedException.class, () -> inTest.newFileChannel(options));
				Assertions.assertTrue(e.retryable());
			}

			verify(firstCiphertextChannel).close();
			assertDetachedAsReplaced();
		}

		@Test
		@DisplayName("a first channel without a file key from before opening detects a file of another size that replaced the opened one")
		void testFirstChannelWithoutKeyDetectsReplacementBySize() throws IOException {
			when(replacementAttributes.size()).thenReturn(100L);
			when(firstCiphertextChannel.size()).thenReturn(0L);
			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenThrow(new NoSuchFileException("joinedFile"));
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenReturn(replacementAttributes);
				var e = Assertions.assertThrows(CiphertextReplacedException.class, () -> inTest.newFileChannel(options));
				Assertions.assertTrue(e.retryable());
			}

			verify(firstCiphertextChannel).close();
			assertDetachedAsReplaced();
		}

		@Test
		@DisplayName("a first channel without a file key from before opening captures the key of the file it opened")
		void testFirstChannelWithoutKeyCapturesKeyAfterOpen() throws IOException {
			when(firstAttributes.size()).thenReturn(100L);
			when(firstCiphertextChannel.size()).thenReturn(100L);
			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenThrow(new NoSuchFileException("joinedFile"));
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenReturn(firstAttributes);
				inTest.newFileChannel(options);
			}

			Assertions.assertFalse(ciphertextFileKey.matches(REPLACEMENT_KEY));
		}

		@Test
		@DisplayName("a first channel keeps the file key from before opening if the attributes after opening are unavailable")
		void testFirstChannelKeepsKeyWithoutAttributesAfterOpen() throws IOException {
			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenReturn(FIRST_KEY);
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenThrow(new IOException("stat failed"));
				inTest.newFileChannel(options);
			}

			Assertions.assertFalse(ciphertextFileKey.matches(REPLACEMENT_KEY));
		}

		@Test
		@DisplayName("a first channel takes the last-modified time from the file whose key it captured")
		void testFirstChannelTakesModifiedTimeOfCapturedFile() throws IOException {
			openFirstChannel();

			Assertions.assertEquals(FIRST_MODIFIED, inTest.getLastModifiedTime());
		}

		@Test
		@DisplayName("a first channel keeps a last-modified time set while it opens")
		void testFirstChannelKeepsModifiedTimeSetDuringOpen() throws IOException {
			var setDuringOpen = FileTime.from(Instant.parse("2024-01-01T00:00:00Z"));
			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenAnswer(invocation -> {
					inTest.setLastModifiedTime(setDuringOpen);
					return FIRST_KEY;
				});
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenReturn(firstAttributes);
				inTest.newFileChannel(options);
			}

			Assertions.assertEquals(setDuringOpen, inTest.getLastModifiedTime());
		}

		@Test
		@DisplayName("a joining channel keeps the open file's last-modified time")
		void testJoiningChannelKeepsModifiedTime() throws IOException {
			openFirstChannel();
			var modifiedByWrite = FileTime.from(Instant.parse("2024-01-01T00:00:00Z"));
			inTest.setLastModifiedTime(modifiedByWrite);

			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenReturn(FIRST_KEY);
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenReturn(firstAttributes);
				inTest.newFileChannel(options);
			}

			verify(chunkIO).registerChannel(candidate, false);
			Assertions.assertEquals(modifiedByWrite, inTest.getLastModifiedTime());
		}

		@Test
		@DisplayName("a joining open with DELETE_ON_CLOSE detaches the open file after unlinking it, even without a captured file key")
		void testDeleteOnCloseJoinWithoutFileKeyDetaches() throws IOException {
			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenThrow(new IOException("stat failed"));
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenThrow(new IOException("stat failed"));
				inTest.newFileChannel(options);
			}
			Assertions.assertFalse(ciphertextFileKey.isCaptured());

			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenThrow(new NoSuchFileException("joinedFile"));
				inTest.newFileChannel(deleteOnCloseOptions);
			}

			Assertions.assertNull(inTest.getCurrentFilePath());
			verify(closeListener).close(path, inTest);
		}

		@Test
		@DisplayName("a deleted open file refuses new channels with IllegalStateException")
		void testDeletedFile() {
			inTest.updateCurrentFilePath(null);

			Assertions.assertThrows(IllegalStateException.class, () -> inTest.newFileChannel(options));
		}

		@Test
		@DisplayName("an open with DELETE_ON_CLOSE that unlinked the ciphertext detaches the open file, so that concurrent openers retry")
		void testDeleteOnCloseUnlinkingDetaches() throws IOException {
			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenReturn(FIRST_KEY);
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenThrow(new NoSuchFileException("joinedFile"));
				var channel = inTest.newFileChannel(deleteOnCloseOptions);
				Assertions.assertSame(cleartextChannel, channel);
			}

			verify(chunkIO).registerChannel(firstCiphertextChannel, false);
			Assertions.assertNull(inTest.getCurrentFilePath());
			verify(closeListener).close(path, inTest);
			var e = Assertions.assertThrows(CiphertextReplacedException.class, () -> inTest.newFileChannel(options));
			Assertions.assertTrue(e.retryable());
		}

		@Test
		@DisplayName("an open with DELETE_ON_CLOSE that detects a replacement after opening is not retryable")
		void testDeleteOnCloseReplacementNotRetryable() throws IOException {
			openFirstChannel();

			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(path)).thenReturn(FIRST_KEY);
				fileKeys.when(() -> CiphertextFileKey.readAttributes(path)).thenReturn(replacementAttributes);
				var e = Assertions.assertThrows(CiphertextReplacedException.class, () -> inTest.newFileChannel(deleteOnCloseOptions));
				Assertions.assertFalse(e.retryable());
			}

			verify(candidate).close();
			Assertions.assertNull(inTest.getCurrentFilePath());
		}

	}

	@Nested
	@DisplayName("comparing file headers of joining channels")
	class HeaderCheck {

		private final Cryptor realCryptor = CryptorProvider.forScheme(CryptorProvider.Scheme.SIV_GCM).provide(new Masterkey(new byte[64]), new SecureRandom());
		private final int headerSize = realCryptor.fileHeaderCryptor().headerSize();
		private FileSystem fileSystem;
		private AtomicReference<Path> path;
		private FileHeaderHolder realHeaderHolder;
		private OpenCryptoFile inTest;

		@BeforeEach
		void setup() {
			fileSystem = Jimfs.newFileSystem(Configuration.unix());
			path = new AtomicReference<>(fileSystem.getPath("/file"));
			realHeaderHolder = new FileHeaderHolder(realCryptor, path);
			inTest = new OpenCryptoFile(closeListener, realCryptor, realHeaderHolder, chunkIO, ciphertextFileKey, path, new AtomicLong(-1L), new AtomicReference<>(), lastModified, openCryptoFileComponent, inUseManager, useToken);
		}

		@AfterEach
		void tearDown() throws IOException {
			fileSystem.close();
		}

		private byte[] newEncryptedHeader() {
			var encrypted = realCryptor.fileHeaderCryptor().encryptHeader(realCryptor.fileHeaderCryptor().create());
			var bytes = new byte[encrypted.remaining()];
			encrypted.get(bytes);
			return bytes;
		}

		private byte[] cachedHeader() {
			var cached = realHeaderHolder.getEncrypted().duplicate().rewind();
			var bytes = new byte[cached.remaining()];
			cached.get(bytes);
			return bytes;
		}

		private FileChannel serving(byte[] content, int maxBytesPerRead) throws IOException {
			FileChannel channel = mock(FileChannel.class);
			when(channel.read(any(ByteBuffer.class), anyLong())).thenAnswer(invocation -> {
				ByteBuffer dst = invocation.getArgument(0);
				long position = invocation.getArgument(1);
				if (position >= content.length) {
					return -1;
				}
				int n = (int) Math.min(Math.min(dst.remaining(), maxBytesPerRead), content.length - position);
				dst.put(content, (int) position, n);
				return n;
			});
			return channel;
		}

		@Test
		@DisplayName("a loaded header on disk matches")
		void testSameLoadedHeader() throws IOException {
			var header = newEncryptedHeader();
			realHeaderHolder.loadExisting(serving(header, Integer.MAX_VALUE));

			Assertions.assertTrue(inTest.verifySameCiphertext(null, serving(header, Integer.MAX_VALUE)));
		}

		@Test
		@DisplayName("a created and written header on disk matches")
		void testSameCreatedHeader() throws IOException {
			realHeaderHolder.createNew();
			realHeaderHolder.headerIsPersisted().set(true);

			Assertions.assertTrue(inTest.verifySameCiphertext(null, serving(cachedHeader(), Integer.MAX_VALUE)));
		}

		@Test
		@DisplayName("another header on disk doesn't match")
		void testDifferentHeader() throws IOException {
			realHeaderHolder.loadExisting(serving(newEncryptedHeader(), Integer.MAX_VALUE));

			Assertions.assertFalse(inTest.verifySameCiphertext(null, serving(newEncryptedHeader(), Integer.MAX_VALUE)));
		}

		@Test
		@DisplayName("an empty file matches a header not written yet")
		void testEmptyFileWithUnpersistedHeader() throws IOException {
			realHeaderHolder.createNew();

			Assertions.assertTrue(inTest.verifySameCiphertext(null, serving(new byte[0], Integer.MAX_VALUE)));
		}

		@Test
		@DisplayName("another header doesn't match a header not written yet")
		void testOtherHeaderWithUnpersistedHeader() throws IOException {
			realHeaderHolder.createNew();

			Assertions.assertFalse(inTest.verifySameCiphertext(null, serving(newEncryptedHeader(), Integer.MAX_VALUE)));
		}

		@Test
		@DisplayName("a file shorter than a persisted header doesn't match")
		void testShortFileWithPersistedHeader() throws IOException {
			var header = newEncryptedHeader();
			realHeaderHolder.loadExisting(serving(header, Integer.MAX_VALUE));

			Assertions.assertFalse(inTest.verifySameCiphertext(null, serving(Arrays.copyOf(header, headerSize / 2), Integer.MAX_VALUE)));
			Assertions.assertFalse(inTest.verifySameCiphertext(null, serving(new byte[0], Integer.MAX_VALUE)));
		}

		@Test
		@DisplayName("a header read in several parts matches")
		void testHeaderReadInParts() throws IOException {
			var header = newEncryptedHeader();
			realHeaderHolder.loadExisting(serving(header, Integer.MAX_VALUE));

			Assertions.assertTrue(inTest.verifySameCiphertext(null, serving(header, headerSize / 2 + 1)));
		}

		@Test
		@DisplayName("an empty file matches a header that gets written while reading")
		void testHeaderPersistedWhileReading() throws IOException {
			realHeaderHolder.createNew();
			FileChannel channel = mock(FileChannel.class);
			when(channel.read(any(ByteBuffer.class), anyLong())).thenAnswer(invocation -> {
				realHeaderHolder.headerIsPersisted().set(true);
				return -1;
			});

			Assertions.assertTrue(inTest.verifySameCiphertext(null, channel));
		}

		@Test
		@DisplayName("without file keys, a channel joining after the header changed on disk detaches the open file")
		void testReplacedHeaderWithoutFileKeys() throws IOException {
			Files.write(path.get(), newEncryptedHeader());
			var options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.READ), readonlyFlag);
			when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
			when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
			var cleartextChannel = mock(CleartextFileChannel.class);
			when(channelComponent.channel()).thenReturn(cleartextChannel);
			var attributesWithoutKey = mock(BasicFileAttributes.class);
			when(attributesWithoutKey.lastModifiedTime()).thenReturn(FileTime.fromMillis(0));

			try (var fileKeys = mockStatic(CiphertextFileKey.class)) {
				fileKeys.when(() -> CiphertextFileKey.read(any())).thenReturn(null);
				fileKeys.when(() -> CiphertextFileKey.readAttributes(any())).thenReturn(attributesWithoutKey);
				inTest.newFileChannel(options);
				inTest.newFileChannel(options);
				Files.write(path.get(), newEncryptedHeader());
				var e = Assertions.assertThrows(CiphertextReplacedException.class, () -> inTest.newFileChannel(options));
				Assertions.assertTrue(e.retryable());
			}

			Assertions.assertNull(inTest.getCurrentFilePath());
			verify(closeListener).close(fileSystem.getPath("/file"), inTest);
		}

	}

}
