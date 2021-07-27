package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.health.api.CommonDetailKeys;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

/**
 * A ciphertext dir ending with c9r or c9s but does not contain a valid signature file.
 * <p>
 * Valid signature files for c9r are {@value org.cryptomator.cryptofs.common.Constants#DIR_FILE_NAME} and {@value org.cryptomator.cryptofs.common.Constants#SYMLINK_FILE_NAME}.
 * Valid signature files for c9s are the ones for c9r and {@value org.cryptomator.cryptofs.common.Constants#CONTENTS_FILE_NAME}.
 */
public class UnknownType implements DiagnosticResult {

	final Path cipherDir;

	UnknownType(Path c9rDir) {
		this.cipherDir = c9rDir;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	/*
	TODO: remove directory? might cause data loss (for shortened files)
	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		DiagnosticResult.super.fix(pathToVault, config, masterkey, cryptor);
	}
	 */

	@Override
	public String toString() {
		return String.format("Encrypted dir %s of unknown type.", cipherDir);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(CommonDetailKeys.ENCRYPTED_PATH, cipherDir.toString());
	}
}
