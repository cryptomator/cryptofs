package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * The directory id is used more than once.
 */
public class DirIdCollision implements DiagnosticResult {

	final String dirId;
	final Path file;
	final Path otherFile;

	DirIdCollision(String dirId, Path file, Path otherFile) {
		this.dirId = dirId;
		this.file = file;
		this.otherFile = otherFile;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return String.format("Directory ID reused: %s found in %s and %s", dirId, file, otherFile);
	}
}
