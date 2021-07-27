package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * A c9r or c9s dir containing exactly one, valid signature file.
 *
 * Valid signature files for c9r are {@value org.cryptomator.cryptofs.common.Constants#DIR_FILE_NAME} and {@value org.cryptomator.cryptofs.common.Constants#SYMLINK_FILE_NAME}.
 * Valid signature files for c9s are the ones for c9r and {@value org.cryptomator.cryptofs.common.Constants#CONTENTS_FILE_NAME}.
 */
public class KnownType implements DiagnosticResult {

	final Path cipherDir;

	KnownType(Path ctfDirectory) {
		this.cipherDir = ctfDirectory;
	}

	@Override
	public Severity getSeverity() {
		return Severity.GOOD;
	}
}
