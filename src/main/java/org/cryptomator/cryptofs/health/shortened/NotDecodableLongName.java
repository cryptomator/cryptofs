package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.CommonDetailKeys;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.Map;

/**
 * A name.c9s file with a syntactical <em>incorrect</em> string.
 * <p>
 * A string is only correct if
 * <ul>
 *     <li> it ends with {@value org.cryptomator.cryptofs.common.Constants#CRYPTOMATOR_FILE_SUFFIX} and </li>
 *     <li> excluding the aforementioned suffix, is base64url encoded</li>
 * </ul>
 * <p>
 * A special case represents the diagnostic result {@link TrailingBytesInNameFile}.
 *
 * @see TrailingBytesInNameFile
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
				"Stored String", longName);
	}

	@Override
	public String toString() {
		return String.format("String \"%s\" stored in %s is not a valid Cryptomator filename.", longName, nameFile);
	}
}
