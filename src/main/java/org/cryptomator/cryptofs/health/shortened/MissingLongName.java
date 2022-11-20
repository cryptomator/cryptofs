package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.List;

/**
 * A c9s directory with a missing long name.
 * <p>
 * A long name is missing if either
 *   <ul>
 * <li> the file {@value org.cryptomator.cryptofs.common.Constants#INFLATED_FILE_NAME} does not exist</li>
 * <li> it is not a regular file</li>
 *   </ul>
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
		return String.format("Shortened resource %s either misses %s or the file has invalid content.", c9sDir, Constants.INFLATED_FILE_NAME);
	}

	@Override
	public List<Path> getCausingCiphertextNodes(){
		return List.of(c9sDir);
	}

}
