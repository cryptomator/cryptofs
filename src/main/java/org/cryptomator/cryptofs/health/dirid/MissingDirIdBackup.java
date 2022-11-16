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
import java.util.Optional;

/**
 * The dir id backup file {@value org.cryptomator.cryptofs.common.Constants#DIR_BACKUP_FILE_NAME} is missing.
 */
public record MissingDirIdBackup(String dirId, Path contentDir) implements DiagnosticResult {

	@Override
	public Severity getSeverity() {
		return Severity.INFO;
	}

	@Override
	public String toString() {
		return String.format("Directory ID backup for directory %s is missing.", contentDir);
	}

	//visible for testing
	void fix(Path pathToVault, Cryptor cryptor) throws IOException {
		Path absCipherDir = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(contentDir);
		DirectoryIdBackup.backupManually(cryptor, new CryptoPathMapper.CiphertextDirectory(dirId, absCipherDir));
	}

	@Override
	public Optional<Fix> getFix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		return Optional.of(() -> fix(pathToVault, cryptor));
	}
}
