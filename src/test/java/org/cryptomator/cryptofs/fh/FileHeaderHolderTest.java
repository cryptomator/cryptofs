package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.event.DecryptionFailedEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class FileHeaderHolderTest {

	static {
		System.setProperty("org.slf4j.simpleLogger.log.org.cryptomator.cryptofs.ch.FileHeaderHolder", "trace");
		System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
		System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "HH:mm:ss.SSS");
	}

	private final FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private final Cryptor cryptor = mock(Cryptor.class);
	private final Path cipherPath = mock(Path.class, "cipherFile.c9r");
	private final CryptoPath clearPath = mock(CryptoPath.class, "openFile.txt");
	private final AtomicReference<ClearAndCipherPath> pathRef = new AtomicReference<>(new ClearAndCipherPath(clearPath, cipherPath));
	private final Consumer<FilesystemEvent> eventConsumer = mock(Consumer.class);

	private FileHeaderHolder inTest;

	@BeforeEach
	public void setup() throws IOException {
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		when(fileHeaderCryptor.encryptHeader(Mockito.any())).thenReturn(ByteBuffer.wrap(new byte[0]));
		inTest = new FileHeaderHolder(eventConsumer, cryptor, pathRef);
	}

	@Nested
	@DisplayName("existing header")
	public class ExistingHeader {

		private FileHeader headerToLoad = Mockito.mock(FileHeader.class);
		private FileChannel channel = Mockito.mock(FileChannel.class);

		@BeforeEach
		public void setup() throws IOException, AuthenticationFailedException {
			byte[] headerBytes = "leHeader".getBytes(StandardCharsets.US_ASCII);
			when(fileHeaderCryptor.headerSize()).thenReturn(headerBytes.length);
			when(channel.read(Mockito.any(ByteBuffer.class), Mockito.eq(0l))).thenAnswer(invocation -> {
				ByteBuffer buf = invocation.getArgument(0);
				Assertions.assertEquals(headerBytes.length, buf.capacity());
				buf.put(headerBytes);
				return headerBytes.length;
			});
			when(fileHeaderCryptor.decryptHeader(Mockito.argThat(buf -> StandardCharsets.US_ASCII.decode(buf).toString().equals("leHeader")))).thenReturn(headerToLoad);
		}

		@Test
		@DisplayName("load success")
		public void testLoadExisting() throws IOException, AuthenticationFailedException {
			FileHeader loadedHeader1 = inTest.loadExisting(channel);
			FileHeader loadedHeader2 = inTest.get();
			FileHeader loadedHeader3 = inTest.get();
			Assertions.assertSame(headerToLoad, loadedHeader1);
			Assertions.assertSame(headerToLoad, loadedHeader2);
			Assertions.assertSame(headerToLoad, loadedHeader3);

			verify(fileHeaderCryptor, times(1)).decryptHeader(Mockito.any());
			Assertions.assertNotNull(inTest.get());
			Assertions.assertNotNull(inTest.getEncrypted());
			Assertions.assertTrue(inTest.headerIsPersisted().get());
		}

		@Test
		@DisplayName("load failure")
		public void testLoadExistingFailure() {
			Mockito.doThrow(AuthenticationFailedException.class).when(fileHeaderCryptor).decryptHeader(Mockito.any());

			Assertions.assertThrows(IOException.class, () -> inTest.loadExisting(channel));
			var isDecryptionFailedEvent = (ArgumentMatcher<FilesystemEvent>) ev -> ev instanceof DecryptionFailedEvent;
			verify(eventConsumer).accept(ArgumentMatchers.argThat(isDecryptionFailedEvent));
		}

	}

	@Nested
	@DisplayName("new header")
	public class NewHeader {

		private FileHeader headerToCreate = Mockito.mock(FileHeader.class);

		@BeforeEach
		public void setup() throws IOException {
			when(fileHeaderCryptor.create()).thenReturn(headerToCreate);
		}

		@AfterEach
		public void tearDown() throws AuthenticationFailedException {
			verify(fileHeaderCryptor, Mockito.never()).decryptHeader(Mockito.any());
		}

		@Test
		@DisplayName("create")
		public void testCreateNew() {
			FileHeader createdHeader1 = inTest.createNew();
			FileHeader createdHeader2 = inTest.get();
			FileHeader createdHeader3 = inTest.get();
			Assertions.assertSame(headerToCreate, createdHeader1);
			Assertions.assertSame(headerToCreate, createdHeader2);
			Assertions.assertSame(headerToCreate, createdHeader3);

			verify(fileHeaderCryptor, times(1)).create();
			Assertions.assertNotNull(inTest.get());
			Assertions.assertNotNull(inTest.getEncrypted());
			Assertions.assertFalse(inTest.headerIsPersisted().get());
		}

	}

}
