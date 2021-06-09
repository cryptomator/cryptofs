package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.ENCRYPTED_PATH;

/**
 * An orphan directory is a detached node, not referenced by any dir.c9r file.
 */
public class OrphanDir implements DiagnosticResult {

	final Path dir;

	OrphanDir(Path dir) {
		this.dir = dir;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("Orphan directory: %s", dir);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(ENCRYPTED_PATH, dir.toString());
	}

	// fix: create new dirId inside of L+F dir and rename existing dir accordingly.
}
