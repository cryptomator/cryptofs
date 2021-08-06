package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * A c9s directory with a missing long name.
 * <p>
 * A long name is missing if either
 *     <ul>
 * 		<li> the file {@Value org.cryptomator.cryptofs.Constants#INFLATED_FILE_NAME} does not exist</li>
 * 		<li> it is not a regular file</li>
 * 		<li> (TODO: it is not decryptable)</li>
 *     </ul>
 * </p>
 */
public class MissingLongName implements DiagnosticResult {

	final Path c9sDir;

	public MissingLongName(Path c9sDir) {this.c9sDir = c9sDir;}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return String.format("Shortened resource %s either misses %s or the file has invalid content.", c9sDir, Constants.INFLATED_FILE_NAME); //TODO
	}

	/*
		Fix: create new name. BUUUT: without dirId not possible
	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		//TODO
	}
	 */

}
