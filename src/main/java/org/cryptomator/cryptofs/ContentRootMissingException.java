package org.cryptomator.cryptofs;

import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

public class ContentRootMissingException extends NoSuchFileException {

	public ContentRootMissingException(Path encryptedVaultRootDir) {
		super(encryptedVaultRootDir.toString());
	}
}
