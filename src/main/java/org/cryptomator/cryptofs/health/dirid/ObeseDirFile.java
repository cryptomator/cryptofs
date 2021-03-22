package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * The dir.c9r file's size is too large.
 */
public class ObeseDirFile implements DiagnosticResult {

	private final Path dirFile;
	private final long size;

	ObeseDirFile(Path dirFile, long size) {
		this.dirFile = dirFile;
		this.size = size;
	}

	@Override
	public Severity getServerity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("Unexpected file size of %s: %d should be ≤ %d", dirFile, size, Constants.MAX_DIR_FILE_LENGTH);
	}

	// potential fix: assign new dir id, move target dir

}
