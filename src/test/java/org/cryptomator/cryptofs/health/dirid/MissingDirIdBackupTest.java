package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.CiphertextDirectory;
import org.cryptomator.cryptofs.DirectoryIdBackup;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Path;

public class MissingDirIdBackupTest {

	@TempDir
	public Path pathToVault;
	private MissingDirIdBackup result;

	@DisplayName("MissingDirIdBackup result has a fix")
	@Test
	public void testGetFix() {
		result = new MissingDirIdBackup("foobar", Mockito.mock(Path.class));
		Assertions.assertTrue(result.getFix(Mockito.mock(Path.class), Mockito.mock(VaultConfig.class), Mockito.mock(Masterkey.class), Mockito.mock(Cryptor.class)).isPresent());
	}


	@DisplayName("The fix calls dirId backup class with correct parameters")
	@Test
	public void testFix() throws IOException {
		Path cipherDir = Path.of("d/ri/diculous-30-char-pseudo-hash");
		String dirId = "1234-456789-1234";
		try (var dirIdBackupMock = Mockito.mockStatic(DirectoryIdBackup.class)) {
			dirIdBackupMock.when(() -> DirectoryIdBackup.backupManually(Mockito.any(), Mockito.any())).thenAnswer(Answers.RETURNS_SMART_NULLS);
			Cryptor cryptor = Mockito.mock(Cryptor.class);

			result = new MissingDirIdBackup(dirId, cipherDir);
			result.fix(pathToVault, cryptor);

			var expectedPath = pathToVault.resolve(cipherDir);
			ArgumentMatcher<CiphertextDirectory> cipherDirMatcher = obj -> obj.dirId().equals(dirId) && obj.path().isAbsolute() && obj.path().equals(expectedPath);
			dirIdBackupMock.verify(() -> DirectoryIdBackup.backupManually(Mockito.eq(cryptor), Mockito.argThat(cipherDirMatcher)), Mockito.times(1));
		}
	}
}
