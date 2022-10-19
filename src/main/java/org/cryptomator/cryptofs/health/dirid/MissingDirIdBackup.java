package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.DirectoryIdBackup;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Path;

/**
 * The dir id backup file {@value org.cryptomator.cryptofs.common.Constants#DIR_ID_FILE} is missing.
 */
public record MissingDirIdBackup(String dirId, Path cipherDir) implements DiagnosticResult {

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("Directory ID backup for directory %s is missing.", cipherDir);
	}

	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		Path absCipherDir = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(cipherDir);
		DirectoryIdBackup.backupManually(cryptor, new CryptoPathMapper.CiphertextDirectory(dirId, absCipherDir));
	}
}
