package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class TrailingNullBytesInNameFileTest {

	@TempDir
	public Path pathToVault;

	private TrailingBytesInNameFile result;
	private Path dataDir;
	private Path cipherDir;

	@BeforeEach
	public void init() throws IOException {
		dataDir = pathToVault.resolve("d");
		cipherDir = dataDir.resolve("00/0000");
		Files.createDirectories(cipherDir);
	}

	@DisplayName("TrailingNullBytes result has a fix")
	@Test
	public void testGetFix() {
		result = new TrailingBytesInNameFile(Mockito.mock(Path.class), "foobar");
		Assertions.assertTrue(result.getFix(Mockito.mock(Path.class), Mockito.mock(VaultConfig.class), Mockito.mock(Masterkey.class), Mockito.mock(Cryptor.class)).isPresent());
	}

	@Test
	@DisplayName("Successful fix only removes trailing null bytes")
	public void testSuccessfulFixRemovesTrailingNullBytes() throws IOException {
		//prepare
		Path c9sDir = cipherDir.resolve("foo==.c9s");
		Path nameFile = c9sDir.resolve("name.c9s");
		var longName = "bar==.c9r\0\0\0";
		result = new TrailingBytesInNameFile(pathToVault.relativize(nameFile), longName);

		Files.createDirectory(c9sDir);
		Files.writeString(nameFile, longName, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

		//execute
		result.fix(pathToVault);

		//evaluate
		Assertions.assertEquals("bar==.c9r", Files.readString(nameFile, StandardCharsets.UTF_8));
	}
}
