package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.DirectoryIdBackup;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Path;

/**
 * TODO: adjust DirIdCheck
 */
public class MissingDirIdFile implements DiagnosticResult {

	private final Path cipherDir;
	private final String dirId;

	MissingDirIdFile(String dirId, Path cipherDir)  {
		this.cipherDir = cipherDir;
		this.dirId = dirId;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN; //TODO: decide severity
	}

	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		DirectoryIdBackup dirIdBackup = new DirectoryIdBackup(cryptor);
		dirIdBackup.execute(new CryptoPathMapper.CiphertextDirectory(dirId,cipherDir));
	}
}
