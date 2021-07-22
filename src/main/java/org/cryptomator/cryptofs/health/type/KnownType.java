package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

public class KnownType implements DiagnosticResult {

	private final Path cipherDir;

	KnownType(Path ctfDirectory) {
		this.cipherDir = ctfDirectory;
	}

	@Override
	public Severity getSeverity() {
		return Severity.GOOD;
	}
}
