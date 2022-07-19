package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
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
		var resultSpy = Mockito.spy(result);
		Mockito.doNothing().when(resultSpy).createDirIdFile(Mockito.any(), Mockito.any());

		resultSpy.fix(pathToVault, Mockito.mock(VaultConfig.class), Mockito.mock(Masterkey.class), cryptor);

		var expectedPath = pathToVault.resolve("d/ri/diculous-30-char-pseudo-hash");
		ArgumentMatcher<CryptoPathMapper.CiphertextDirectory> cipherDirMatcher = obj -> obj.dirId.equals(dirId) && obj.path.endsWith(expectedPath);
		Mockito.verify(resultSpy, Mockito.times(1)).createDirIdFile(Mockito.eq(cryptor), Mockito.argThat(cipherDirMatcher));
		var attr = Assertions.assertDoesNotThrow(() -> Files.readAttributes(expectedPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS));
		Assertions.assertTrue(attr.isDirectory());
	}

	@DisplayName("If dirId file creation fails, fix fails ")
	@Test
	public void testFixFailsOnFailingDirIdFile() throws IOException {
		var dirIdHash = "ridiculous-30-char-pseudo-hash";
		Mockito.doReturn(dirIdHash).when(fileNameCryptor).hashDirectoryId(dirId);
		var resultSpy = Mockito.spy(result);
		Mockito.doThrow(new IOException("Access denied")).when(resultSpy).createDirIdFile(Mockito.any(), Mockito.any());

		Assertions.assertThrows(IOException.class, () -> resultSpy.fix(pathToVault, Mockito.mock(VaultConfig.class), Mockito.mock(Masterkey.class), cryptor));
	}
}
