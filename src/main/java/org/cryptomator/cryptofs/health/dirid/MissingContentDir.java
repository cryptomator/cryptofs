package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.CryptoPathMapper;
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

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID;
import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID_FILE;

/**
 * Valid dir.c9r file, nonexisting content dir
 */
public class MissingContentDir implements DiagnosticResult {

	final String dirId;
	final Path file;

	MissingContentDir(String dirId, Path file) {
		this.dirId = dirId;
		this.file = file;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("dir.c9r file (%s) points to non-existing directory.", file);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_ID, dirId, //
				DIR_ID_FILE, file.toString());
	}

	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		var dirIdHash = cryptor.fileNameCryptor().hashDirectoryId(dirId);
		Path dirPath = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(dirIdHash.substring(0, 2)).resolve(dirIdHash.substring(2, 30));
		Files.createDirectories(dirPath);
		createDirIdFile(cryptor, new CryptoPathMapper.CiphertextDirectory(dirId, dirPath));
	}

	//visible for testing
	void createDirIdFile(Cryptor cryptor, CryptoPathMapper.CiphertextDirectory cipherDirObj) throws IOException {
		new DirectoryIdBackup(cryptor).execute(cipherDirObj);
	}
}
