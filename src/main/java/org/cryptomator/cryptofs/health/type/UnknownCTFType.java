package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

public class UnknownCTFType implements DiagnosticResult {

	private final Path ctfDirectory;

	UnknownCTFType(Path ctfDirectory) {
		this.ctfDirectory = ctfDirectory;
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
