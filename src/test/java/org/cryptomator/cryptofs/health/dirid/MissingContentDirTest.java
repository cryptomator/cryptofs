package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.DirectoryIdBackup;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

public class MissingContentDirTest {

	@TempDir
	public Path pathToVault;

	private MissingContentDir result;
	private String dirId;
	private Cryptor cryptor;
	private FileNameCryptor fileNameCryptor;

	@BeforeEach
	public void init() {
		Path p = Mockito.mock(Path.class, "ignored");
		dirId = "1234-456789-1234";
		result = new MissingContentDir(dirId, p);

		cryptor = Mockito.mock(Cryptor.class);
		fileNameCryptor = Mockito.mock(FileNameCryptor.class);
		Mockito.doReturn(fileNameCryptor).when(cryptor).fileNameCryptor();
		Mockito.doReturn(fileNameCryptor).when(cryptor).fileNameCryptor();
	}

	@DisplayName("After fix the content dir including dirId file exists ")
	@Test
	public void testFix() throws IOException {
		var dirIdHash = "ridiculous-30-char-pseudo-hash";
		Mockito.doReturn(dirIdHash).when(fileNameCryptor).hashDirectoryId(dirId);
		try (var dirIdBackupMock = Mockito.mockStatic(DirectoryIdBackup.class)) {
			dirIdBackupMock.when(() -> DirectoryIdBackup.backupManually(Mockito.any(), Mockito.any())).thenAnswer(Answers.RETURNS_SMART_NULLS);

			result.fix(pathToVault, Mockito.mock(VaultConfig.class), Mockito.mock(Masterkey.class), cryptor);

			var expectedPath = pathToVault.resolve("d/ri/diculous-30-char-pseudo-hash");
			ArgumentMatcher<CryptoPathMapper.CiphertextDirectory> cipherDirMatcher = obj -> obj.dirId.equals(dirId) && obj.path.endsWith(expectedPath);
			dirIdBackupMock.verify(() -> DirectoryIdBackup.backupManually(Mockito.eq(cryptor), Mockito.argThat(cipherDirMatcher)), Mockito.times(1));
			var attr = Assertions.assertDoesNotThrow(() -> Files.readAttributes(expectedPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS));
			Assertions.assertTrue(attr.isDirectory());
		}
	}

	@DisplayName("If dirid.c9r creation fails, fix fails ")
	@Test
	public void testFixFailsOnFailingDirIdFile() throws IOException {
		var dirIdHash = "ridiculous-30-char-pseudo-hash";
		try (var dirIdBackupMock = Mockito.mockStatic(DirectoryIdBackup.class)) {
			Mockito.doReturn(dirIdHash).when(fileNameCryptor).hashDirectoryId(dirId);
			dirIdBackupMock.when(() -> DirectoryIdBackup.backupManually(Mockito.any(), Mockito.any())).thenThrow(new IOException("Access denied"));

			Assertions.assertThrows(IOException.class, () -> result.fix(pathToVault, Mockito.mock(VaultConfig.class), Mockito.mock(Masterkey.class), cryptor));
		}
	}
}
