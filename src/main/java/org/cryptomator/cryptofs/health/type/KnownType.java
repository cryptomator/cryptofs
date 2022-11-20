package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.health.api.CommonDetailKeys;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * A c9r or c9s dir containing exactly one, valid type file.
 */
public class KnownType implements DiagnosticResult {

	final Path cipherDir;
	final CiphertextFileType type;

	KnownType(Path ctfDirectory, CiphertextFileType type) {
		this.cipherDir = ctfDirectory;
		this.type = type;
	}

	@Override
	public Severity getSeverity() {
		return Severity.GOOD;
	}

	@Override
	public String toString() {
		return String.format("Node %s with determined type %s.", cipherDir, type);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(CommonDetailKeys.ENCRYPTED_PATH, cipherDir.toString(),
				"Type", type.name());
	}

	@Override
	public List<Path> affectedCiphertextNodes(){
		return List.of(cipherDir);
	}
}
