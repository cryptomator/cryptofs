package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Path;

/**
 * A c9s directory where the name of the directory is not a Base64URL encoded SHA1-hash of the contents in {@Value org.cryptomator.cryptofs.Constants#INFLATED_FILE_NAME}
 */
public class LongShortNamesMismatch implements DiagnosticResult {

	final Path c9sDir;
	final String encryptedLongName;

	public LongShortNamesMismatch(Path c9sDir, String encryptedLongName) {
		this.c9sDir = c9sDir;
		this.encryptedLongName = encryptedLongName;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("Filename of %s is not a base64url encoded SHA1 hash of %s.", c9sDir, encryptedLongName);
	}

	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		//TODO: discuss security implications
	}

}
