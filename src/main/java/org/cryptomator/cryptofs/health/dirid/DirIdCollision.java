package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID;
import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_FILE;

/**
 * The directory id is used more than once.
 */
public class DirIdCollision implements DiagnosticResult {

	final String dirId;
	final Path dirFile;
	final Path otherDirFile;

	DirIdCollision(String dirId, Path dirFile, Path otherDirFile) {
		this.dirId = dirId;
		this.dirFile = dirFile;
		this.otherDirFile = otherDirFile;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return String.format("Directory ID reused: %s found in %s and %s", dirId, dirFile, otherDirFile);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_ID, dirId, //
				DIR_FILE, dirFile.toString(), //
				"Other " + DIR_FILE, otherDirFile.toString());
	}
}
