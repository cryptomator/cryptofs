package org.cryptomator.cryptofs.health.dirid;

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

public class LooseDirFileTest {

	LooseDirFile result;

	@DisplayName("LooseDirFile has a fix")
	@Test
	public void testGetFix() {
		result = new LooseDirFile(Mockito.mock(Path.class));
		Assertions.assertTrue(result.getFix(Mockito.mock(Path.class), Mockito.mock(VaultConfig.class), Mockito.mock(Masterkey.class), Mockito.mock(Cryptor.class)).isPresent());
	}

	@DisplayName("LooseDirFile fix deletes loose file")
	@Test
	public void testFix(@TempDir Path tmpDir) throws IOException {
		Path dirFile = tmpDir.resolve("loose.c9r");

		Files.createFile(dirFile);
		result = new LooseDirFile(dirFile.getFileName());
		result.fix(tmpDir);
		Assertions.assertTrue(Files.notExists(dirFile));
	}

}
