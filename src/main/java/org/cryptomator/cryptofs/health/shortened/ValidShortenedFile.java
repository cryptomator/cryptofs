package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * TODO: doc doc doc
 * 			- the duckumentation duck
 *		   __
 *	   ___( o)>
 *	   \ <_. )
 *		`---'   hjw
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
		return String.format("TODO %s", c9sDir);
	}

}
