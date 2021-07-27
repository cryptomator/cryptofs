package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.health.api.CommonDetailKeys;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

/**
 * A ciphertext dir ending with c9r or c9s but does contain more than one valid signature file.
 * <p>
 * Valid signature files for c9r are {@value org.cryptomator.cryptofs.common.Constants#DIR_FILE_NAME} and {@value org.cryptomator.cryptofs.common.Constants#SYMLINK_FILE_NAME}.
 * Valid signature files for c9s are the ones for c9r and {@value org.cryptomator.cryptofs.common.Constants#CONTENTS_FILE_NAME}.
 */
public class AmbiguousType implements DiagnosticResult {

	final Path cipherDir;
	final Set<CiphertextFileType> possibleTypes;

	AmbiguousType(Path cipherDir, Set<CiphertextFileType> possibleTypes) {
		this.cipherDir = cipherDir;
		this.possibleTypes = possibleTypes;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return String.format("Encrypted dir %s of ambiguous type. Possible types are: %s", cipherDir, possibleTypes);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(CommonDetailKeys.ENCRYPTED_PATH, cipherDir.toString(),
				"Possible Types", possibleTypes.toString());
	}
}
