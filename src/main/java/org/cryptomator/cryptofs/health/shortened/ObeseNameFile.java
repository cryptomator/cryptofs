package org.cryptomator.cryptofs.health.shortened;

import org.cryptomator.cryptofs.LongFileNameProvider;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;

import java.nio.file.Path;

/**
 * A shortend file name file which exceeds the maximum size of {@Value org.cryptomator.cryptofs.LongFileNameProvider#MAX_FILENAME_BUFFER_SIZE} bytes.
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
		return String.format("Long filename file %s with size %d exceeds limit of %d for this type.", nameFile, size, LongFileNameProvider.MAX_FILENAME_BUFFER_SIZE);
	}

}
