package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Path;

/**
 * TODO: doc doc doc
 * 			- the duckumentation duck
 *		   __
 *	   ___( o)>
 *	   \ <_. )
 *		`---'   hjw
 */
public class LongShortNamesMismatch implements DiagnosticResult {

	final Path c9sDir;

	public LongShortNamesMismatch(Path c9sDir) {this.c9sDir = c9sDir;}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("TODO %s",c9sDir); //TODO
	}

	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		//TODO: security implications
	}

}
