package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class UnknownTypeTest {

	UnknownType result;
	VaultConfig vaultConfig = Mockito.mock(VaultConfig.class);
	Masterkey masterkey = Mockito.mock(Masterkey.class);
	Cryptor cryptor = Mockito.mock(Cryptor.class);

	@Test
	public void testFix(@TempDir Path tmpDir) throws IOException {
		Path c9rDir = Path.of("some.c9r");
		Path absolutePath = tmpDir.resolve(c9rDir);
		Files.createDirectory(absolutePath);
		result = new UnknownType(c9rDir);

		result.fix(tmpDir, vaultConfig, masterkey, cryptor);

		Assertions.assertTrue(Files.notExists(absolutePath));
	}

}
