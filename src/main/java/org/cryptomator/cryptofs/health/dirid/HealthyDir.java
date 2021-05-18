package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * Valid dir.c9r file, existing target dir
 */
public class HealthyDir implements DiagnosticResult {

	final String dirId;
	final Path dirIdFile;
	final Path dir;

	HealthyDir(String dirId, Path dirIdFile, Path dir) {
		this.dirId = dirId;
		this.dirIdFile = dirIdFile;
		this.dir = dir;
	}

	@Override
	public Severity getSeverity() {
		return Severity.GOOD;
	}

	@Override
	public String toString() {
		return String.format("Good directory %s (%s) -> %s", dirIdFile, dirId, dir);
	}
}
