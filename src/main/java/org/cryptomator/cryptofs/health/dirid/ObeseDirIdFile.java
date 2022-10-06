package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID_FILE;

/**
 * The dir.c9r file's size is too large.
 */
public class ObeseDirIdFile implements DiagnosticResult {

	final Path dirIdFile;
	final long size;

	ObeseDirIdFile(Path dirIdFile, long size) {
		this.dirIdFile = dirIdFile;
		this.size = size;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return String.format("Unexpected file size of %s: %d should be ≤ %d", dirIdFile, size, Constants.MAX_DIR_FILE_LENGTH);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_ID_FILE, dirIdFile.toString(), //
				"Size", Long.toString(size));
	}
	// potential fix: assign new dir id, move target dir

}
