package org.cryptomator.cryptofs.fh;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.ReadonlyFlag;
import org.cryptomator.cryptofs.ch.ChannelComponent;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
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
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class OpenCryptoFileTest {

	private static FileSystem FS;
	private static Path CURRENT_FILE_PATH;
	private CryptoPath clearPath = mock(CryptoPath.class, "cleartext.txt");
	private AtomicReference<ClearAndCipherPath> paths;
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

	@BeforeAll
	public static void setup() {
		FS = Jimfs.newFileSystem("OpenCryptoFileTest", Configuration.unix().toBuilder().setAttributeViews("basic", "posix").build());
		CURRENT_FILE_PATH = FS.getPath("currentCipherFile.c9r");
	}

	@BeforeEach
	public void beforeEach() {
		this.paths = new AtomicReference<>(new ClearAndCipherPath(clearPath, CURRENT_FILE_PATH));
	}

	@AfterAll
	public static void tearDown() throws IOException {
		FS.close();
	}

	@Test
	public void testCloseTriggersCloseListener() {
		OpenCryptoFile openCryptoFile = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, paths, fileSize, lastModified, openCryptoFileComponent);
		openCryptoFile.close();
		verify(closeListener).close(paths.get().ciphertextPath(), openCryptoFile);
	}

	// tests https://github.com/cryptomator/cryptofs/issues/51
	@Test
	public void testCloseImmediatelyIfOpeningFirstChannelFails() {
		UncheckedIOException expectedException = new UncheckedIOException(new IOException("fail!"));
		EffectiveOpenOptions options = Mockito.mock(EffectiveOpenOptions.class);
		Mockito.when(options.createOpenOptionsForEncryptedFile()).thenThrow(expectedException);
		OpenCryptoFile openCryptoFile = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, paths, fileSize, lastModified, openCryptoFileComponent);

		UncheckedIOException exception = Assertions.assertThrows(UncheckedIOException.class, () -> {
			openCryptoFile.newFileChannel(options);
		});
		Assertions.assertSame(expectedException, exception);
		verify(closeListener).close(paths.get().ciphertextPath(), openCryptoFile);
	}

	@Test
	@DisplayName("Opening a file channel with TRUNCATE_EXISTING calls truncate(0) on the cleartextChannel")
	public void testCleartextChannelTruncateCalledOnTruncateExisting() throws IOException {
		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING), readonlyFlag);
		var cleartextChannel = mock(CleartextFileChannel.class);
		Mockito.when(headerHolder.get()).thenReturn(Mockito.mock(FileHeader.class));
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		Mockito.when(fileHeaderCryptor.headerSize()).thenReturn(42);
		Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentFactory);
		Mockito.when(channelComponentFactory.create(any(), any(), any())).thenReturn(channelComponent);
		Mockito.when(channelComponent.channel()).thenReturn(cleartextChannel);
		OpenCryptoFile openCryptoFile = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, paths, fileSize, lastModified, openCryptoFileComponent);

		openCryptoFile.newFileChannel(options);
		verify(cleartextChannel).truncate(0L);
	}

	@Nested
	@DisplayName("Testing ::initFileHeader")
	public class InitFilHeaderTests {

		EffectiveOpenOptions options = Mockito.mock(EffectiveOpenOptions.class);
		FileChannel cipherFileChannel = Mockito.mock(FileChannel.class, "cipherFilechannel");
		OpenCryptoFile inTest = new OpenCryptoFile(closeListener, cryptor, headerHolder, chunkIO, paths, fileSize, lastModified, openCryptoFileComponent);

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
			CURRENT_FILE_PATH = FS.getPath("currentCipherFile.c9r");
			paths = new AtomicReference<>(new ClearAndCipherPath(clearPath, CURRENT_FILE_PATH));
			openCryptoFile = new OpenCryptoFile(closeListener,cryptor, headerHolder, chunkIO, paths, realFileSize, lastModified, openCryptoFileComponent);
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
			var attrs = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-x---"));
			EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), readonlyFlag);
			FileChannel ch = openCryptoFile.newFileChannel(options, attrs);
			Assertions.assertSame(cleartextFileChannel, ch);
			verify(chunkIO).registerChannel(ciphertextChannel.get(), true);
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
			verify(closeListener, Mockito.never()).close(paths.get().ciphertextPath(), openCryptoFile);
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
