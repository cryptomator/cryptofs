package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class UnknownTypeTest {

	UnknownType result;

	@DisplayName("UnkownType result has a fix")
	@Test
	public void testGetFix() {
		result = new UnknownType(Mockito.mock(Path.class));
		Assertions.assertTrue(result.getFix(Mockito.mock(Path.class), Mockito.mock(VaultConfig.class), Mockito.mock(Masterkey.class), Mockito.mock(Cryptor.class)).isPresent());
	}

	@Test
	public void testFix(@TempDir Path tmpDir) throws IOException {
		Path c9rDir = Path.of("some.c9r");
		Path absolutePath = tmpDir.resolve(c9rDir);
		Files.createDirectory(absolutePath);
		result = new UnknownType(c9rDir);

		result.fix(tmpDir);

		Assertions.assertTrue(Files.notExists(absolutePath));
	}

}
