package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * The directory id is used more than once.
 */
public class DirIdCollision extends DiagnosticResult {

	private final String dirId;
	private final Path file;
	private final Path otherFile;

	public DirIdCollision(String dirId, Path file, Path otherFile) {
		super(Severity.CRITICAL);
		this.dirId = dirId;
		this.file = file;
		this.otherFile = otherFile;
	}

	@Override
	public String toString() {
		return String.format("Directory ID reused: %s found in %s and %s", dirId, file, otherFile);
	}
}
