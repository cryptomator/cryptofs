package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * Valid dir.c9r file, existing target dir
 */
public class HealthyDir extends DiagnosticResult {

	private final String dirId;
	private final Path dirIdFile;
	private final Path dir;

	protected HealthyDir(String dirId, Path dirIdFile, Path dir) {
		super(Severity.GOOD);
		this.dirId = dirId;
		this.dirIdFile = dirIdFile;
		this.dir = dir;
	}

	@Override
	public String toString() {
		return String.format("Good directory %s (%s) -> %s", dirIdFile, dirId, dir);
	}
}
