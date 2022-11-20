package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;
import java.util.List;

/**
 * A valid shortened resource according to the Cryptomator vault specification.
 */
public class ValidShortenedFile implements DiagnosticResult {

	final Path c9sDir;

	public ValidShortenedFile(Path c9sDir) {this.c9sDir = c9sDir;}

	@Override
	public Severity getSeverity() {
		return Severity.GOOD;
	}

	@Override
	public String toString() {
		return String.format("Found valid shortened resource at %s.", c9sDir);
	}

	@Override
	public List<Path> affectedCiphertextNodes(){
		return List.of(c9sDir);
	}
}
