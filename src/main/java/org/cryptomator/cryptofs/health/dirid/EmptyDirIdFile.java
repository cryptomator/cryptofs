package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID_FILE;

/**
 * A diagnostic result of an empty directory id file (dir.c9r).
 * <p>
 * Even though the empty directory ID exists, it is reserved for the root node of the crypto filesystem only.
 * Due to its nature, the root node has no corresponding dir.c9r file.
 * As a consequence, actual dir.c9r files must not be empty, otherwise it is an error in the vault structure.
 *
 * @see org.cryptomator.cryptofs.common.Constants#ROOT_DIR_ID
 */
public class EmptyDirIdFile implements DiagnosticResult {

	final Path dirIdFile;

	public EmptyDirIdFile(Path dirIdFile) {this.dirIdFile = dirIdFile;}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return String.format("File %s is empty, expected content", dirIdFile);
	}

	/*
	TODO: remove dirFile and parent dir, Change severity to WARN
	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		Files.delete(dirFile);
		Files.delete(dirFile.getParent());

	}
	 */

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_ID_FILE, dirIdFile.toString());
	}
}
