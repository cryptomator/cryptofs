package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * TODO: doc doc doc
 * 		-- the dockumentation duck
 *                __
 *              <(o )___
 *               ( ._> /
 *                `---'   hjw
 */
public class AmbiguousType implements DiagnosticResult {

	private final Path cipherDir;

	AmbiguousType(Path cipherDir) {
		this.cipherDir = cipherDir;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}
}
