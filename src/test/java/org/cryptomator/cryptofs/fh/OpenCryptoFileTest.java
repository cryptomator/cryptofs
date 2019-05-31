package org.cryptomator.cryptofs.fh;

import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.ReadonlyFlag;
import org.cryptomator.cryptofs.ch.ChannelCloseListener;
import org.cryptomator.cryptofs.ch.ChannelComponent;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
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
import java.time.Instant;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class OpenCryptoFileTest {

	private static FileSystem FS;
	private static AtomicReference<Path> CURRENT_FILE_PATH;
	private ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);
	private FileCloseListener closeListener = mock(FileCloseListener.class);
	private ChunkCache chunkCache = mock(ChunkCache.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private FileHeaderHolder headerHolder = mock(FileHeaderHolder.class);
	private FileHeader header = mock(FileHeader.class);
	private ChunkIO chunkIO = mock(ChunkIO.class);
	private AtomicLong fileSize = new AtomicLong(-1l);
	private AtomicReference<Instant> lastModified = new AtomicReference(Instant.ofEpochMilli(0));
	private OpenCryptoFileComponent openCryptoFileComponent = mock(OpenCryptoFileComponent.class);
	private ChannelComponent.Builder channelComponentBuilder = mock(ChannelComponent.Builder.class);
	private ChannelComponent channelComponent = mock(ChannelComponent.class);

	@BeforeAll
	public static void setup() {
		FS = Jimfs.newFileSystem("OpenCryptoFileTest");
		CURRENT_FILE_PATH = new AtomicReference<>(FS.getPath("currentFile"));
	}

	@AfterAll
	public static void tearDown() throws IOException {
		FS.close();
	}

	@Test
	public void testCloseTriggersCloseListener() {
		OpenCryptoFile openCryptoFile = new OpenCryptoFile(closeListener, chunkCache, cryptor, headerHolder, chunkIO, CURRENT_FILE_PATH, fileSize, lastModified, openCryptoFileComponent);
		openCryptoFile.close();
		verify(closeListener).close(CURRENT_FILE_PATH.get(), openCryptoFile);
	}

	// tests https://github.com/cryptomator/cryptofs/issues/51
	@Test
	public void testCloseImmediatelyIfOpeningFirstChannelFails() {
		UncheckedIOException expectedException = new UncheckedIOException(new IOException("fail!"));
		EffectiveOpenOptions options = Mockito.mock(EffectiveOpenOptions.class);
		Mockito.when(options.createOpenOptionsForEncryptedFile()).thenThrow(expectedException);
		OpenCryptoFile openCryptoFile = new OpenCryptoFile(closeListener, chunkCache, cryptor, headerHolder, chunkIO, CURRENT_FILE_PATH, fileSize, lastModified, openCryptoFileComponent);

		UncheckedIOException exception = Assertions.assertThrows(UncheckedIOException.class, () -> {
			openCryptoFile.newFileChannel(options);
		});
		Assertions.assertSame(expectedException, exception);
		verify(closeListener).close(CURRENT_FILE_PATH.get(), openCryptoFile);
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	@DisplayName("FileChannels")
	class FileChannelFactoryTest {

		private OpenCryptoFile openCryptoFile;
		private CleartextFileChannel cleartextFileChannel;
		private AtomicReference<ChannelCloseListener> listener;
		private AtomicReference<FileChannel> ciphertextChannel;

		@BeforeAll
		public void setup() throws IOException {
			openCryptoFile = new OpenCryptoFile(closeListener, chunkCache, cryptor, headerHolder, chunkIO, CURRENT_FILE_PATH, fileSize, lastModified, openCryptoFileComponent);
			cleartextFileChannel = mock(CleartextFileChannel.class);
			listener = new AtomicReference<>();
			ciphertextChannel = new AtomicReference<>();

			Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentBuilder);
			Mockito.when(channelComponentBuilder.ciphertextChannel(Mockito.any())).thenAnswer(invocation -> {
				ciphertextChannel.set(invocation.getArgument(0));
				return channelComponentBuilder;
			});
			Mockito.when(channelComponentBuilder.openOptions(Mockito.any())).thenReturn(channelComponentBuilder);
			Mockito.when(channelComponentBuilder.onClose(Mockito.any())).thenAnswer(invocation -> {
				listener.set(invocation.getArgument(0));
				return channelComponentBuilder;
			});
			Mockito.when(channelComponentBuilder.fileHeader(Mockito.any())).thenReturn(channelComponentBuilder);
			Mockito.when(channelComponentBuilder.mustWriteHeader(Mockito.anyBoolean())).thenReturn(channelComponentBuilder);
			Mockito.when(channelComponentBuilder.build()).thenReturn(channelComponent);
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
			EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), readonlyFlag);
			FileChannel ch = openCryptoFile.newFileChannel(options);
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
			verify(closeListener, Mockito.never()).close(CURRENT_FILE_PATH.get(), openCryptoFile);
		}

		@Test
		@Order(13)
		@DisplayName("getting size succeeds after creating second file channel")
		public void testGetSizeAfterCreatingSecondFileChannel() {
			Assertions.assertEquals(0l, openCryptoFile.size().get());
		}


		@Test
		@Order(20)
		@DisplayName("TRUNCATE_EXISTING leads to chunk cache invalidation")
		public void testTruncateExistingInvalidatesChunkCache() throws IOException {
			Files.write(CURRENT_FILE_PATH.get(), new byte[0]);
			EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE), readonlyFlag);
			openCryptoFile.newFileChannel(options);
			verify(chunkCache).invalidateAll();
		}

		@Test
		@Order(100)
		@DisplayName("closeListener triggers chunkIO.unregisterChannel()")
		public void triggerCloseListener() throws IOException {
			Assumptions.assumeTrue(listener.get() != null);
			Assumptions.assumeTrue(ciphertextChannel.get() != null);

			listener.get().closed(cleartextFileChannel);
			verify(chunkIO).unregisterChannel(ciphertextChannel.get());
		}

	}

}
