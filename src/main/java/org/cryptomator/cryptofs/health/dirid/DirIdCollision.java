package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID;
import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID_FILE;

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

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_ID, dirId, //
				DIR_ID_FILE, file.toString(), //
				"Other " + DIR_ID_FILE, otherFile.toString());
	}
}
