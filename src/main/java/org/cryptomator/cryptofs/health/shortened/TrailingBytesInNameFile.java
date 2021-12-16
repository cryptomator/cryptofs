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

import static org.cryptomator.cryptofs.common.Constants.CRYPTOMATOR_FILE_SUFFIX;

/**
 * Result and fix for bug https://github.com/cryptomator/cryptofs/issues/121
 */
public class TrailingBytesInNameFile implements DiagnosticResult {

	private final Path nameFile;
	private final String longName;

	public TrailingBytesInNameFile(Path nameFile, String longName) {
		this.nameFile = nameFile;
		this.longName = longName;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		var startIndexTrailingBytes = longName.indexOf(CRYPTOMATOR_FILE_SUFFIX) + CRYPTOMATOR_FILE_SUFFIX.length();
		Files.writeString(pathToVault.resolve(nameFile), //
				longName.substring(0, startIndexTrailingBytes), //
				StandardCharsets.UTF_8, //
				StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(CommonDetailKeys.ENCRYPTED_PATH, nameFile.toString(), //
				"Encrypted Long Name", longName);
	}
}
