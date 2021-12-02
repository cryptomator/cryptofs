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
import java.nio.file.Files;
import java.nio.file.Path;

public class LongShortNamesMismatchTest {

	@TempDir
	public Path pathToVault;

	private LongShortNamesMismatch result;
	private Path dataDir;
	private Path cipherDir;

	@BeforeEach
	public void init() throws IOException {
		dataDir = pathToVault.resolve("d");
		cipherDir = dataDir.resolve("00/0000");
		Files.createDirectories(cipherDir);
	}

	@Test
	@DisplayName("a successful fix only renames the c9s directory")
	public void testSuccessfulFixRenamesResource() throws IOException {
		//prepare
		Path c9sDir = cipherDir.resolve("foo==.c9s");
		result = new LongShortNamesMismatch(c9sDir, "bar==.c9s");

		Files.createDirectory(c9sDir);

		//execute
		result.fix(pathToVault, Mockito.mock(VaultConfig.class), Mockito.mock(Masterkey.class), Mockito.mock(Cryptor.class));

		//evaluate
		Path expectedC9sDir = c9sDir.resolveSibling("bar==.c9s");
		Assertions.assertTrue(Files.exists(expectedC9sDir));
		Assertions.assertTrue(Files.notExists(c9sDir));
	}

}
