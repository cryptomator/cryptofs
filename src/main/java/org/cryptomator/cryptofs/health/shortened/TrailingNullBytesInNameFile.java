package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.CommonDetailKeys;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;

/**
 * Result and fix for bug https://github.com/cryptomator/cryptofs/issues/121
 */
public class TrailingNullBytesInNameFile implements DiagnosticResult {

	private final Path nameFile;
	private final String longName;

	public TrailingNullBytesInNameFile(Path nameFile, String longName) {
		this.nameFile = nameFile;
		this.longName = longName;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		Files.writeString(pathToVault.resolve(nameFile), longName.substring(0, longName.indexOf('\0')), StandardCharsets.UTF_8, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(CommonDetailKeys.ENCRYPTED_PATH, nameFile.toString(), //
				"Encrypted Long Name", longName);
	}
}
