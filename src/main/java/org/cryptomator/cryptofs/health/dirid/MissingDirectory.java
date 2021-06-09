package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID;
import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID_FILE;

/**
 * Valid dir.c9r file, nonexisting dir
 */
public class MissingDirectory implements DiagnosticResult {

	//TODO: maybe add not-existing dir path
	final String dirId;
	final Path file;

	MissingDirectory(String dirId, Path file) {
		this.dirId = dirId;
		this.file = file;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("dir.c9r file (%s) points to non-existing directory.", file);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_ID, dirId, //
				DIR_ID_FILE, file.toString());
	}
	// fix: create dir?
}
