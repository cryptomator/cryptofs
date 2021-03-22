package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * Valid dir.c9r file, nonexisting dir
 */
public class MissingDirectory implements DiagnosticResult {

	private final String dirId;
	private final Path file;

	MissingDirectory(String dirId, Path file) {
		this.dirId = dirId;
		this.file = file;
	}

	@Override
	public Severity getServerity() {
		return Severity.WARN;
	}

	@Override
	public String description() {
		return String.format("dir.c9r file (%s) points to non-existing directory.", file);
	}

	// fix: create dir?
}