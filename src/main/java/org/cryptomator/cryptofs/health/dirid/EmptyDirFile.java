package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.DIR_ID_FILE;

public class EmptyDirFile implements DiagnosticResult {

	final Path dirFile;

	public EmptyDirFile(Path dirFile) {this.dirFile = dirFile;}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return String.format("File %s is empty, expected content", dirFile);
	}

	/*
	TODO: remove dirFile and parent dir, Change severity to WARN
	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		Files.delete(dirFile);
		Files.delete(dirFile.getParent());

	}
	 */

	@Override
	public Map<String, String> details() {
		return Map.of(DIR_ID_FILE, dirFile.toString());
	}
}
