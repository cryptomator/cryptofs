package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID;
import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_FILE;
import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.ENCRYPTED_PATH;

/**
 * Valid dir.c9r file, existing target dir
 */
public class HealthyDir implements DiagnosticResult {

	final String dirId;
	final Path dirFile;
	final Path dir;

	HealthyDir(String dirId, Path dirFile, Path dir) {
		this.dirId = dirId;
		this.dirFile = dirFile;
		this.dir = dir;
	}

	@Override
	public Severity getSeverity() {
		return Severity.GOOD;
	}

	@Override
	public String toString() {
		return String.format("Good directory %s (%s) -> %s", dirFile, dirId, dir);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_ID, dirId, //
				DIR_FILE, dirFile.toString(), //
				ENCRYPTED_PATH, dir.toString());
	}
}
