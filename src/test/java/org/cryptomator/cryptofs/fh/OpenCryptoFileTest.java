package org.cryptomator.cryptofs.fh;

import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.ReadonlyFlag;
import org.cryptomator.cryptofs.ch.ChannelCloseListener;
import org.cryptomator.cryptofs.ch.ChannelComponent;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
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
import org.junit.jupiter.api.parallel.Execution;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class OpenCryptoFileTest {

	private FileSystem fs;
	private AtomicReference<Path> currentFilePath;
	private ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);
	private FileCloseListener closeListener = mock(FileCloseListener.class);
	private FileHeaderHandler fileHeaderHandler = mock(FileHeaderHandler.class);
	private ChunkIO chunkIO = mock(ChunkIO.class);
	private AtomicLong fileSize = new AtomicLong();
	private AtomicReference<Instant> lastModified = new AtomicReference(Instant.ofEpochMilli(0));
	private OpenCryptoFileComponent openCryptoFileComponent = mock(OpenCryptoFileComponent.class);
	private ChannelComponent.Builder channelComponentBuilder = mock(ChannelComponent.Builder.class);
	private ChannelComponent channelComponent = mock(ChannelComponent.class);

	private OpenCryptoFile inTest;

	@BeforeEach
	public void setup() throws IOException {
		fs = Jimfs.newFileSystem("OpenCryptoFileTest");
		currentFilePath = new AtomicReference<>(fs.getPath("currentFile"));

		inTest = new OpenCryptoFile(closeListener, chunkIO, fileHeaderHandler, currentFilePath, fileSize, lastModified, openCryptoFileComponent);
	}

	@AfterEach
	public void tearDown() throws IOException {
		fs.close();
	}

	@Test
	public void testCloseTriggersCloseListener() {
		inTest.close();
		verify(closeListener).close(currentFilePath.get(), inTest);
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	@DisplayName("FileChannels")
	class FileChannelFactoryTest {

		private EffectiveOpenOptions options;
		private CleartextFileChannel cleartextFileChannel;
		private AtomicReference<ChannelCloseListener> listener;
		private AtomicReference<FileChannel> ciphertextChannel;

		@BeforeAll
		public void setup() throws IOException {
			options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), readonlyFlag);
			cleartextFileChannel = mock(CleartextFileChannel.class);
			listener = new AtomicReference<>();
			ciphertextChannel = new AtomicReference<>();

			Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentBuilder);
			Mockito.when(channelComponentBuilder.ciphertextChannel(Mockito.any())).thenAnswer(invocation -> {
				ciphertextChannel.set(invocation.getArgument(0));
				return channelComponentBuilder;
			});
			Mockito.when(channelComponentBuilder.openOptions(options)).thenReturn(channelComponentBuilder);
			Mockito.when(channelComponentBuilder.onClose(Mockito.any())).thenAnswer(invocation -> {
				listener.set(invocation.getArgument(0));
				return channelComponentBuilder;
			});
			Mockito.when(channelComponentBuilder.build()).thenReturn(channelComponent);
			Mockito.when(channelComponent.channel()).thenReturn(cleartextFileChannel);
		}

		@Test
		@Order(0)
		@DisplayName("create new FileChannel")
		public void createFileChannel() throws IOException {
			FileChannel ch = inTest.newFileChannel(options);
			Assertions.assertSame(cleartextFileChannel, ch);
			verify(chunkIO).registerChannel(ciphertextChannel.get(), true);
		}

		@Test
		@Order(100)
		@DisplayName("closeListener triggers fileHeaderHandler.persistIfNeeded()")
		public void triggerCloseListener() throws IOException {
			Assumptions.assumeTrue(listener.get() != null);
			Assumptions.assumeTrue(ciphertextChannel.get() != null);

			listener.get().closed(cleartextFileChannel);
			verify(fileHeaderHandler).persistIfNeeded();
			verify(chunkIO).unregisterChannel(ciphertextChannel.get());
		}

	}

}
