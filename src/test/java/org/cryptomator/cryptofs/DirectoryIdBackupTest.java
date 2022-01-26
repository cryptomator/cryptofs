package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

@ExtendWith(MockitoExtension.class)
public class DirectoryIdBackupTest {

	@TempDir
	Path contentPath;

	private String dirId = "12345678";
	private CryptoPathMapper.CiphertextDirectory cipherDirObject;
	@Mock
	private EncryptingWritableByteChannel encChannel;
	@Mock
	private Cryptor cryptor;

	private DirectoryIdBackup dirIdBackup;


	@BeforeEach
	public void init() {
		cipherDirObject = new CryptoPathMapper.CiphertextDirectory(dirId, contentPath);
		dirIdBackup = new DirectoryIdBackup(cryptor);
	}

	@Test
	public void testIdFileCreated() throws IOException {
		try (MockedStatic<DirectoryIdBackup> backupMock = Mockito.mockStatic(DirectoryIdBackup.class)) {
			backupMock.when(() -> DirectoryIdBackup.wrapEncryptionAround(Mockito.any(), Mockito.eq(cryptor))).thenReturn(encChannel);
			Mockito.when(encChannel.write(Mockito.any())).thenReturn(0);

			dirIdBackup.execute(cipherDirObject);

			Assertions.assertTrue(Files.exists(contentPath.resolve(Constants.DIR_ID_FILE)));
		}
	}

	@Test
	public void testContentIsWritten() throws IOException {
		Mockito.when(encChannel.write(Mockito.any())).thenReturn(0);
		var expectedWrittenContent = ByteBuffer.wrap(dirId.getBytes(StandardCharsets.UTF_8));

		try (MockedStatic<DirectoryIdBackup> backupMock = Mockito.mockStatic(DirectoryIdBackup.class)) {
			backupMock.when(() -> DirectoryIdBackup.wrapEncryptionAround(Mockito.any(), Mockito.eq(cryptor))).thenReturn(encChannel);

			dirIdBackup.execute(cipherDirObject);

			Mockito.verify(encChannel, Mockito.times(1)).write(Mockito.argThat(b -> b.equals(expectedWrittenContent)));
		}
	}

}
