package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

public class KnownCTFType implements DiagnosticResult {

	private final Path ctfDirectory;

	KnownCTFType(Path ctfDirectory) {
		this.ctfDirectory = ctfDirectory;
	}

	@Override
	public Severity getSeverity() {
		return Severity.GOOD;
	}
}
