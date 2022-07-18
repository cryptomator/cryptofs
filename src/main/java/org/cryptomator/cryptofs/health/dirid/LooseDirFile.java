package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID_FILE;

public class LooseDirFile implements DiagnosticResult {

	final Path dirFile;

	LooseDirFile(Path dirFile) {
		this.dirFile = dirFile;
	}

	@Override
	public Severity getSeverity() {
		return Severity.INFO;
	}

	@Override
	public String toString() {
		return String.format("A dir.c9r without proper parent found: (%s). .", dirFile);
	}

	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		Files.deleteIfExists(dirFile);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_ID_FILE, dirFile.toString());
	}
}
