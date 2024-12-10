package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.dirid.OrphanContentDirTest;
import org.cryptomator.cryptofs.util.TestCryptoException;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

public class DirectoryIdBackupTest {

	@TempDir
	Path contentPath;

	private String dirId = "12345678";
	private Cryptor cryptor;

	private DirectoryIdBackup dirIdBackup;


	@BeforeEach
	public void init() {
		cryptor = Mockito.mock(Cryptor.class);
		dirIdBackup = new DirectoryIdBackup(cryptor);
	}

	@Nested
	public class Write {

		private CiphertextDirectory ciphertextDirectoryObject;
		private EncryptingWritableByteChannel encChannel;

		@BeforeEach
		public void beforeEachWriteTest() {
			ciphertextDirectoryObject = new CiphertextDirectory(dirId, contentPath);
			encChannel = Mockito.mock(EncryptingWritableByteChannel.class);
		}

		@Test
		public void testIdFileCreated() throws IOException {
			var dirIdBackupSpy = spy(dirIdBackup);
			Mockito.doReturn(encChannel).when(dirIdBackupSpy).wrapEncryptionAround(Mockito.any(), Mockito.eq(cryptor));
			Mockito.when(encChannel.write(Mockito.any())).thenReturn(0);

			dirIdBackupSpy.write(ciphertextDirectoryObject);

			Assertions.assertTrue(Files.exists(contentPath.resolve(Constants.DIR_ID_BACKUP_FILE_NAME)));
		}

		@Test
		public void testContentIsWritten() throws IOException {
			var dirIdBackupSpy = spy(dirIdBackup);
			Mockito.doReturn(encChannel).when(dirIdBackupSpy).wrapEncryptionAround(Mockito.any(), Mockito.eq(cryptor));
			Mockito.when(encChannel.write(Mockito.any())).thenReturn(0);
			var expectedWrittenContent = ByteBuffer.wrap(dirId.getBytes(StandardCharsets.US_ASCII));

			dirIdBackupSpy.write(ciphertextDirectoryObject);

			Mockito.verify(encChannel, Mockito.times(1)).write(Mockito.argThat(b -> b.equals(expectedWrittenContent)));
		}
		//TODO: test, what happens if file already exists?
	}

	@Nested
	public class Read {

		private DecryptingReadableByteChannel decChannel;

		@BeforeEach
		public void beforeEachRead() throws IOException {
			var backupFile = contentPath.resolve(Constants.DIR_ID_BACKUP_FILE_NAME);
			Files.writeString(backupFile, dirId, StandardCharsets.US_ASCII, StandardOpenOption.CREATE, StandardOpenOption.WRITE);

			decChannel = mock(DecryptingReadableByteChannel.class);
		}

		@Test
		@DisplayName("If the directory id is longer than 36 characters, throw IllegalStateException")
		public void contentLongerThan36Chars() throws IOException {
			var dirIdBackupSpy = spy(dirIdBackup);
			Mockito.when(dirIdBackupSpy.wrapDecryptionAround(Mockito.any(), Mockito.eq(cryptor))).thenReturn(decChannel);
			Mockito.when(decChannel.read(Mockito.any())).thenReturn(Constants.MAX_DIR_ID_LENGTH + 1);
			Assertions.assertThrows(IllegalStateException.class, () -> dirIdBackupSpy.read(contentPath));
		}

		@Test
		@DisplayName("If the backup file cannot be decrypted, a CryptoException is thrown")
		public void invalidEncryptionThrowsCryptoException() throws IOException {
			var dirIdBackupSpy = spy(dirIdBackup);
			var expectedException = new TestCryptoException();
			Mockito.when(dirIdBackupSpy.wrapDecryptionAround(Mockito.any(), Mockito.eq(cryptor))).thenReturn(decChannel);
			Mockito.when(decChannel.read(Mockito.any())).thenThrow(expectedException);
			var actual = Assertions.assertThrows(CryptoException.class, () -> dirIdBackupSpy.read(contentPath));
			Assertions.assertEquals(expectedException, actual);
		}

		@Test
		@DisplayName("IOException accessing the file is rethrown")
		public void ioException() throws IOException {
			var dirIdBackupSpy = spy(dirIdBackup);
			var expectedException = new IOException("my oh my");
			Mockito.when(dirIdBackupSpy.wrapDecryptionAround(Mockito.any(), Mockito.eq(cryptor))).thenReturn(decChannel);
			Mockito.when(decChannel.read(Mockito.any())).thenThrow(expectedException);
			var actual = Assertions.assertThrows(IOException.class, () -> dirIdBackupSpy.read(contentPath));
			Assertions.assertEquals(expectedException, actual);
		}

		@Test
		@DisplayName("Valid dir id is read from the backup file")
		public void success() throws IOException {
			var dirIdBackupSpy = spy(dirIdBackup);
			var expectedArray = dirId.getBytes(StandardCharsets.US_ASCII);

			Mockito.when(dirIdBackupSpy.wrapDecryptionAround(Mockito.any(), Mockito.eq(cryptor))).thenReturn(decChannel);
			Mockito.doAnswer(invocationOnMock -> {
				var buf = (ByteBuffer) invocationOnMock.getArgument(0);
				buf.put(expectedArray);
				return expectedArray.length;
			}).when(decChannel).read(Mockito.any());

			var readDirId = dirIdBackupSpy.read(contentPath);
			Assertions.assertArrayEquals(expectedArray, readDirId);
		}
	}


}
