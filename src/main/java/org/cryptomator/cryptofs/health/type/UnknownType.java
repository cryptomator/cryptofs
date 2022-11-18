package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.CommonDetailKeys;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

/**
 * Directory ending with {@value Constants#CRYPTOMATOR_FILE_SUFFIX} or {@value Constants#DEFLATED_FILE_SUFFIX}, but without type defining content (i.e., {@value Constants#SYMLINK_FILE_NAME}, {@value Constants#DIR_FILE_NAME} or {@value Constants#CONTENTS_FILE_NAME}).
 * <p>
 * The fix is to delete the directory to free the resource name.
 */
public class UnknownType implements DiagnosticResult {

	final Path cipherDir;

	UnknownType(Path cipherDir) {
		this.cipherDir = cipherDir;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	void fix(Path pathToVault) throws IOException {
		Files.delete(pathToVault.resolve(cipherDir));
	}

	@Override
	public Optional<Fix> getFix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		return Optional.of(() -> fix(pathToVault));
	}

	@Override
	public String toString() {
		return String.format("C9r dir %s of unknown type.", cipherDir);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(CommonDetailKeys.ENCRYPTED_PATH, cipherDir.toString());
	}

}
