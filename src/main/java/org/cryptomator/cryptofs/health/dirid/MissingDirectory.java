package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * Valid dir.c9r file, nonexisting dir
 */
public class MissingDirectory extends DiagnosticResult {

	private final String dirId;
	private final Path file;

	public MissingDirectory(String dirId, Path file) {
		super(Severity.WARN);
		this.dirId = dirId;
		this.file = file;
	}

	@Override
	public String toString() {
		return String.format("dir.c9r file (%s) points to non-existing directory.", file);
	}
}
