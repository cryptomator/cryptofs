package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * The dir.c9r file's size is too large.
 */
public class ObeseDirFile extends DiagnosticResult {

	private final Path dirFile;
	private final long size;

	protected ObeseDirFile(Path dirFile, long size) {
		super(Severity.WARN);
		this.dirFile = dirFile;
		this.size = size;
	}

	@Override
	public String toString() {
		return String.format("Unexpected file size of %s: %d should be ≤ %d", dirFile, size, Constants.MAX_DIR_FILE_LENGTH);
	}

	// potential fix: assign new dir id, move target dir

}
