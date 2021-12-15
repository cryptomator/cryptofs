package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.health.api.CommonDetailKeys;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

/**
 * A name.c9s file, which content is _not_ a base64url encoded string.
 */
public class NotDecodableLongName implements DiagnosticResult {

	private final Path nameFile;
	private final String longName;

	public NotDecodableLongName(Path nameFile, String longName) {
		this.nameFile = nameFile;
		this.longName = longName;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}


	@Override
	public Map<String, String> details() {
		return Map.of(CommonDetailKeys.ENCRYPTED_PATH, nameFile.toString(), //
				"Encrypted Long Name", longName);
	}
}
