package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class DirectoryIdBackupTest {

	@TempDir
	Path contentPath;

	private String dirId = "12345678";
	private CiphertextDirectory ciphertextDirectoryObject;
	private EncryptingWritableByteChannel encChannel;
	private Cryptor cryptor;

	private DirectoryIdBackup dirIdBackup;


	@BeforeEach
	public void init() {
		ciphertextDirectoryObject = new CiphertextDirectory(dirId, contentPath);
		cryptor = Mockito.mock(Cryptor.class);
		encChannel = Mockito.mock(EncryptingWritableByteChannel.class);

		dirIdBackup = new DirectoryIdBackup(cryptor);
	}

	@Test
	public void testIdFileCreated() throws IOException {
		try (MockedStatic<DirectoryIdBackup> backupMock = Mockito.mockStatic(DirectoryIdBackup.class)) {
			backupMock.when(() -> DirectoryIdBackup.wrapEncryptionAround(Mockito.any(), Mockito.eq(cryptor))).thenReturn(encChannel);
			Mockito.when(encChannel.write(Mockito.any())).thenReturn(0);

			dirIdBackup.write(ciphertextDirectoryObject);

			Assertions.assertTrue(Files.exists(contentPath.resolve(Constants.DIR_ID_BACKUP_FILE_NAME)));
		}
	}

	@Test
	public void testContentIsWritten() throws IOException {
		Mockito.when(encChannel.write(Mockito.any())).thenReturn(0);
		var expectedWrittenContent = ByteBuffer.wrap(dirId.getBytes(StandardCharsets.US_ASCII));

		try (MockedStatic<DirectoryIdBackup> backupMock = Mockito.mockStatic(DirectoryIdBackup.class)) {
			backupMock.when(() -> DirectoryIdBackup.wrapEncryptionAround(Mockito.any(), Mockito.eq(cryptor))).thenReturn(encChannel);

			dirIdBackup.write(ciphertextDirectoryObject);

			Mockito.verify(encChannel, Mockito.times(1)).write(Mockito.argThat(b -> b.equals(expectedWrittenContent)));
		}
	}

}
