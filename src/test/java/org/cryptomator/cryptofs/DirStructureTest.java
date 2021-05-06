package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public class DirStructureTest {

	private static final String KEY = "key";
	private static final String CONFIG = "config";

	@TempDir
	Path vaultPath;

	@Test
	public void testNonExistingVaultPathThrowsIOException() {
		Path vaultPath = Path.of("this/certainly/does/not/exist");
		Assumptions.assumeTrue(Files.notExists(vaultPath));

		Assertions.assertThrows(IOException.class, () -> DirStructure.checkDirStructure(vaultPath, CONFIG, KEY));
	}

	@Test
	public void testNonDirectoryVaultPathThrowsIOException() throws IOException {
		Path tmp = vaultPath.resolve("this");
		Files.createFile(tmp);
		Assumptions.assumeTrue(Files.exists(tmp));

		Assertions.assertThrows(IOException.class, () -> DirStructure.checkDirStructure(tmp, CONFIG, KEY));
	}

	@ParameterizedTest(name = "Testing all combinations of data dir, config and masterkey file existence.")
	@MethodSource("provideAllCases")
	public void testAllCombosOfDataAndConfigAndKey(boolean createDataDir, boolean createConfig, boolean createKey, DirStructure expectedResult) throws IOException {
		Path keyPath = vaultPath.resolve(KEY);
		Path configPath = vaultPath.resolve(CONFIG);
		Path dataDir = vaultPath.resolve(Constants.DATA_DIR_NAME);

		if (createDataDir) {
			Files.createDirectory(dataDir);
		}
		if (createConfig) {
			Files.createFile(configPath);
		}
		if (createKey) {
			Files.createFile(keyPath);
		}

		Assertions.assertEquals(expectedResult, DirStructure.checkDirStructure(vaultPath, CONFIG, KEY));
	}

	private static Stream<Arguments> provideAllCases() {
		return Stream.of(
				Arguments.of(true, true, true, DirStructure.VAULT),
				Arguments.of(true, true, false, DirStructure.VAULT),
				Arguments.of(true, false, true, DirStructure.MAYBE_LEGACY),
				Arguments.of(true, false, false, DirStructure.UNRELATED),
				Arguments.of(false, false, false, DirStructure.UNRELATED),
				Arguments.of(false, false, true, DirStructure.UNRELATED),
				Arguments.of(false, true, false, DirStructure.UNRELATED),
				Arguments.of(false, true, true, DirStructure.UNRELATED)
		);
	}

}
