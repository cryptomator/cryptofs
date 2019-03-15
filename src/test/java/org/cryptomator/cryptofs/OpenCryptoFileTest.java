package org.cryptomator.cryptofs;

import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.ch.ChannelComponent;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
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
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.mockito.Mockito.mock;

public class OpenCryptoFileTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private FileSystem fs = Jimfs.newFileSystem("test");
	private AtomicReference<Path> currentFilePath;
	private ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);
	private BasicFileAttributeView attributeView = mock(BasicFileAttributeView.class);
	private Supplier<BasicFileAttributeView> attributeViewSupplier= mock(Supplier.class);
	private BasicFileAttributes attributes = mock(BasicFileAttributes.class);
	private AtomicLong fileSize = new AtomicLong();
	private OpenCryptoFileComponent openCryptoFileComponent = mock(OpenCryptoFileComponent.class);
	private ChannelComponent.Builder channelComponentBuilder = mock(ChannelComponent.Builder.class);
	private ChannelComponent channelComponent = mock(ChannelComponent.class);

	private OpenCryptoFile inTest;

	@Before
	public void setup() throws IOException {
		currentFilePath = new AtomicReference<>(fs.getPath("currentFile"));
		Mockito.when(attributeViewSupplier.get()).thenReturn(attributeView);
		Mockito.when(attributeView.readAttributes()).thenReturn(attributes);
		Mockito.when(attributes.lastModifiedTime()).thenReturn(FileTime.from(Instant.now()));
		Mockito.when(openCryptoFileComponent.newChannelComponent()).thenReturn(channelComponentBuilder);
		Mockito.when(channelComponentBuilder.ciphertextChannel(Mockito.any())).thenReturn(channelComponentBuilder);
		Mockito.when(channelComponentBuilder.openOptions(Mockito.any())).thenReturn(channelComponentBuilder);
		Mockito.when(channelComponentBuilder.lock(Mockito.any())).thenReturn(channelComponentBuilder);
		Mockito.when(channelComponentBuilder.build()).thenReturn(channelComponent);

		inTest = new OpenCryptoFile(attributeViewSupplier, currentFilePath, fileSize, openCryptoFileComponent);
	}

	@Test
	public void testNewFileChannel() throws IOException {
		EffectiveOpenOptions options = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), readonlyFlag);
		CleartextFileChannel cleartextFileChannel = mock(CleartextFileChannel.class);
		Mockito.when(channelComponent.channel()).thenReturn(cleartextFileChannel);

		FileChannel ch = inTest.newFileChannel(options);
		Assert.assertEquals(cleartextFileChannel, ch);
	}

}
