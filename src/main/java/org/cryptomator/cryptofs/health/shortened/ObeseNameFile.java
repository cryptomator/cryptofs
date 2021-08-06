package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * TODO: doc doc doc
 * 			- the duckumentation duck
 * 		   __
 * 	   ___( o)>
 * 	   \ <_. )
 * 		`---'   hjw
 */
public class ObeseNameFile implements DiagnosticResult {

	final Path nameFile;
	final long size;

	public ObeseNameFile(Path nameFile, long size) {
		this.nameFile = nameFile;
		this.size = size;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return String.format("TODO %s %d",nameFile, size); //TODO
	}

}
