package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.CiphertextDirectory;
import org.cryptomator.cryptofs.DirectoryIdBackup;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_FILE;
import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID;

/**
 * Valid dir.c9r file, nonexisting content dir
 */
public class MissingContentDir implements DiagnosticResult {

	final String dirId;
	final Path dirFile;

	MissingContentDir(String dirId, Path dirFile) {
		this.dirId = dirId;
		this.dirFile = dirFile;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("dir.c9r file (%s) points to non-existing directory.", dirFile);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_ID, dirId, //
				DIR_FILE, dirFile.toString());
	}

	//visible for testing
	void fix(Path pathToVault, Cryptor cryptor) throws IOException {
		var dirIdHash = cryptor.fileNameCryptor().hashDirectoryId(dirId);
		Path dirPath = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(dirIdHash.substring(0, 2)).resolve(dirIdHash.substring(2, 32));
		Files.createDirectories(dirPath);
		DirectoryIdBackup.write(cryptor, new CiphertextDirectory(dirId, dirPath));
	}

	@Override
	public Optional<Fix> getFix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		return Optional.of(() -> fix(pathToVault, cryptor));
	}
}
