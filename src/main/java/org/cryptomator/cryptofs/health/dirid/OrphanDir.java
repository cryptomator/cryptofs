package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.ENCRYPTED_PATH;

/**
 * An orphan directory is a detached node, not referenced by any dir.c9r file.
 */
public class OrphanDir implements DiagnosticResult {

	final Path dir;

	OrphanDir(Path dir) {
		this.dir = dir;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("Orphan directory: %s", dir);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(ENCRYPTED_PATH, dir.toString());
	}

	// fix: create new dirId inside of L+F dir and rename existing dir accordingly.
	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		// open filesystem
			//check if l+f dir exists
			// if not, create it
			// create new directory inside l+f with cleartext name based one orphandir path
		// close filesystem

		//find out dirId and ciphertextPath to the created directory

		//for each resource in orphaned ciphertext dir:
		//	move resource to unfiddled dir in l+f and rename resource  (use dirId for associated data)
		//  distinct by directory, symlink and file
		//  e.g. file1, file2, file3,...dir1, dir2, dir3,...,etc
		//  don't forget shortend resource names
		//remove empty, orphaned ciphertextdir
	}
}
