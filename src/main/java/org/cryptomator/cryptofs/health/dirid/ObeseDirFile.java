package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_FILE;

/**
 * The dir.c9r file's size is too large.
 */
public class ObeseDirFile implements DiagnosticResult {

	final Path dirFile;
	final long size;

	ObeseDirFile(Path dirFile, long size) {
		this.dirFile = dirFile;
		this.size = size;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return String.format("Unexpected file size of %s: %d should be ≤ %d", dirFile, size, Constants.MAX_DIR_ID_LENGTH);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_FILE, dirFile.toString(), //
				"Size", Long.toString(size));
	}
	// potential fix: assign new dir id, move target dir

}
