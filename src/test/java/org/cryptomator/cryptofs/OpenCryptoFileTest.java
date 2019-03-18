package org.cryptomator.cryptofs;

import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.ch.ChannelComponent;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

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

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private FileSystem fs;
	private AtomicReference<Path> currentFilePath;
	private ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);
	private OpenCryptoFiles openCryptoFiles = mock(OpenCryptoFiles.class);
	private AtomicLong fileSize = new AtomicLong();
	private AtomicReference<Instant> lastModified = new AtomicReference(Instant.ofEpochMilli(0));
	private OpenCryptoFileComponent openCryptoFileComponent = mock(OpenCryptoFileComponent.class);
	private ChannelComponent.Builder channelComponentBuilder = mock(ChannelComponent.Builder.class);
	private ChannelComponent channelComponent = mock(ChannelComponent.class);

	private OpenCryptoFile inTest;

	@Before
	public void setup() throws IOException {
		fs = Jimfs.newFileSystem("OpenCryptoFileTest");
		currentFilePath = new AtomicReference<>(fs.getPath("currentFile"));
		Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentBuilder);
		Mockito.when(channelComponentBuilder.ciphertextChannel(Mockito.any())).thenReturn(channelComponentBuilder);
		Mockito.when(channelComponentBuilder.openOptions(Mockito.any())).thenReturn(channelComponentBuilder);
		Mockito.when(channelComponentBuilder.onClose(Mockito.any())).thenReturn(channelComponentBuilder);
		Mockito.when(channelComponentBuilder.build()).thenReturn(channelComponent);

		inTest = new OpenCryptoFile(openCryptoFiles, currentFilePath, fileSize, lastModified, openCryptoFileComponent);
	}

	@After
	public void tearDown() throws IOException {
		fs.close();
	}

	@Test
	public void testNewFileChannel() throws IOException {
		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), readonlyFlag);
		CleartextFileChannel cleartextFileChannel = mock(CleartextFileChannel.class);
		Mockito.when(channelComponent.channel()).thenReturn(cleartextFileChannel);

		FileChannel ch = inTest.newFileChannel(options);
		Assert.assertEquals(cleartextFileChannel, ch);
	}

	@Test
	public void testCloseTriggersCloseListener() {
		inTest.close();
		verify(openCryptoFiles).close(inTest);
	}

}
