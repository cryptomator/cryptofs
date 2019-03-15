package org.cryptomator.cryptofs.ch;

import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class FileHeaderHandlerTest {

	static {
		System.setProperty("org.slf4j.simpleLogger.log.org.cryptomator.cryptofs.ch.FileHeaderLoader", "trace");
		System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
		System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "HH:mm:ss.SSS");
	}

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();


	private final FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private final FileChannel channel = mock(FileChannel.class);
	private final Cryptor cryptor = mock(Cryptor.class);
	private final EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
	private final Path path = mock(Path.class, "openFile.txt");
	private final AtomicReference<Path> pathRef = new AtomicReference<>(path);

	private final FileHeaderHandler inTest = new FileHeaderHandler(channel, cryptor, options, pathRef);

	@Before
	public void setup() throws IOException {
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
	}

	@Test
	public void testCreateNew() throws IOException {
		FileHeader headerToCreate = Mockito.mock(FileHeader.class);
		when(options.createNew()).thenReturn(true);
		when(fileHeaderCryptor.create()).thenReturn(headerToCreate);

		FileHeader createdHeader1 = inTest.get();
		FileHeader createdHeader2 = inTest.get();
		FileHeader createdHeader3 = inTest.get();
		Assert.assertSame(headerToCreate, createdHeader1);
		Assert.assertSame(headerToCreate, createdHeader2);
		Assert.assertSame(headerToCreate, createdHeader3);

		verify(fileHeaderCryptor, times(1)).create();
	}

	@Test
	public void testLoadExisting() throws IOException {
		FileHeader headerToLoad = Mockito.mock(FileHeader.class);
		when(fileHeaderCryptor.headerSize()).thenReturn(100);
		when(channel.read(Mockito.any(ByteBuffer.class))).thenAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			Assert.assertEquals(100, buf.capacity());
			buf.put("leHeader".getBytes(StandardCharsets.US_ASCII));
			return null;
		});
		when(fileHeaderCryptor.decryptHeader(Mockito.argThat(buf -> StandardCharsets.US_ASCII.decode(buf).toString().equals("leHeader")))).thenReturn(headerToLoad);

		FileHeader loadedHeader1 = inTest.get();
		FileHeader loadedHeader2 = inTest.get();
		FileHeader loadedHeader3 = inTest.get();
		Assert.assertSame(headerToLoad, loadedHeader1);
		Assert.assertSame(headerToLoad, loadedHeader2);
		Assert.assertSame(headerToLoad, loadedHeader3);

		verify(fileHeaderCryptor, times(1)).decryptHeader(Mockito.any());
	}

}
