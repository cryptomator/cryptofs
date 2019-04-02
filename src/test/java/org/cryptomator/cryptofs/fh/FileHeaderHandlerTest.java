package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class FileHeaderHandlerTest {

	static {
		System.setProperty("org.slf4j.simpleLogger.log.org.cryptomator.cryptofs.ch.FileHeaderLoader", "trace");
		System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
		System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "HH:mm:ss.SSS");
	}

	private final FileHeaderCryptor fileHeaderCryptor = mock(FileHeaderCryptor.class);
	private final ChunkIO chunkIO = mock(ChunkIO.class);
	private final Cryptor cryptor = mock(Cryptor.class);
	private final Path path = mock(Path.class, "openFile.txt");
	private final AtomicReference<Path> pathRef = new AtomicReference<>(path);

	private final FileHeaderHandler inTest = new FileHeaderHandler(chunkIO, cryptor, pathRef);

	@BeforeEach
	public void setup() throws IOException {
		when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
	}

	@Nested
	@DisplayName("existing header")
	class ExistingHeader {

		private FileHeader headerToLoad = Mockito.mock(FileHeader.class);

		@BeforeEach
		public void setup() throws IOException {
			when(chunkIO.size()).thenReturn(100l);
			when(fileHeaderCryptor.headerSize()).thenReturn(100);
			when(chunkIO.read(Mockito.any(ByteBuffer.class), Mockito.eq(0l))).thenAnswer(invocation -> {
				ByteBuffer buf = invocation.getArgument(0);
				Assertions.assertEquals(100, buf.capacity());
				buf.put("leHeader".getBytes(StandardCharsets.US_ASCII));
				return null;
			});
			when(fileHeaderCryptor.decryptHeader(Mockito.argThat(buf -> StandardCharsets.US_ASCII.decode(buf).toString().equals("leHeader")))).thenReturn(headerToLoad);
		}

		@Test
		@DisplayName("load")
		public void testLoadExisting() throws IOException {
			FileHeader loadedHeader1 = inTest.get();
			FileHeader loadedHeader2 = inTest.get();
			FileHeader loadedHeader3 = inTest.get();
			Assertions.assertSame(headerToLoad, loadedHeader1);
			Assertions.assertSame(headerToLoad, loadedHeader2);
			Assertions.assertSame(headerToLoad, loadedHeader3);

			verify(fileHeaderCryptor, times(1)).decryptHeader(Mockito.any());
		}

		@Test
		@DisplayName("don't persist")
		public void testDontPersistDirtyHeader() throws IOException {
			inTest.persistIfNeeded();

			verify(chunkIO, Mockito.never()).write(Mockito.any(), Mockito.eq(0l));
		}

	}

	@Nested
	@DisplayName("new header")
	class NewHeader {

		private FileHeader headerToCreate = Mockito.mock(FileHeader.class);

		@BeforeEach
		public void setup() throws IOException {
			when(chunkIO.size()).thenReturn(0l);
			when(fileHeaderCryptor.create()).thenReturn(headerToCreate);
		}

		@AfterEach
		public void tearDown() {
			verify(fileHeaderCryptor, Mockito.never()).decryptHeader(Mockito.any());
		}

		@Test
		@DisplayName("create")
		public void testCreateNew() throws IOException {
			FileHeader createdHeader1 = inTest.get();
			FileHeader createdHeader2 = inTest.get();
			FileHeader createdHeader3 = inTest.get();
			Assertions.assertSame(headerToCreate, createdHeader1);
			Assertions.assertSame(headerToCreate, createdHeader2);
			Assertions.assertSame(headerToCreate, createdHeader3);

			verify(fileHeaderCryptor, times(1)).create();
		}

		@Test
		@DisplayName("persist")
		public void testPersistDirtyHeader() throws IOException {
			inTest.persistIfNeeded();

			verify(chunkIO).write(Mockito.any(), Mockito.eq(0l));
		}

	}

}
