package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A c9s directory where the name of the directory is not a Base64URL encoded SHA1-hash of the contents in {@value org.cryptomator.cryptofs.common.Constants#INFLATED_FILE_NAME}
 */
public class LongShortNamesMismatch implements DiagnosticResult {

	final Path c9sDir;
	final String expectedShortName;

	public LongShortNamesMismatch(Path c9sDir, String expectedShortName) {
		this.c9sDir = c9sDir;
		this.expectedShortName = expectedShortName;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("Name of %s is not a base64url encoded SHA1 hash of String inside name.c9s.", c9sDir);
	}

	// fix by renaming the parent to the content of name.c9s
	// TODO: once dirId is present, on AlreadyExistsException reattempt move with suffixed name
	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		Files.move(c9sDir, c9sDir.resolveSibling(expectedShortName));
	}

}
