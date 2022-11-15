package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.CommonDetailKeys;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 *  A c9r directory without defining content (symlink or dir file)
 */
public class MissingContentC9rDir implements DiagnosticResult {

	final Path c9rDirectory;

	public MissingContentC9rDir(Path c9rDirectory) {
		this.c9rDirectory = c9rDirectory;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("C9r Directory without identifier file (smylink or dir) found: {}.", c9rDirectory);
	}

	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		Files.deleteIfExists(c9rDirectory);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(CommonDetailKeys.ENCRYPTED_PATH, c9rDirectory.toString());
	}

}
