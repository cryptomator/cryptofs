package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_FILE;

/**
 * Diagnostic result of a dir file without the expected parent directories.
 */
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
	public Optional<Fix> getFix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		return Optional.of(() -> fix(pathToVault));
	}

	//visible for testing
	void fix(Path pathToVault) throws IOException {
		Files.deleteIfExists(pathToVault.resolve(dirFile));
	}

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_FILE, dirFile.toString());
	}

	@Override
	public List<Path> getCausingCiphertextNodes(){
		return List.of(dirFile);
	}
}
