package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

/**
 * TODO: doc, doc, doc
 */
public class UnknownType implements DiagnosticResult {

	private final Path cipherDir;

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
	public Map<String, String> details() {
		return DiagnosticResult.super.details();
	}
}
