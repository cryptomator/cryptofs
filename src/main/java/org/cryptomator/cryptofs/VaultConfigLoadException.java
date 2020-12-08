package org.cryptomator.cryptofs;

/**
 * Failed to parse or verify vault config token.
 */
public class VaultConfigLoadException extends FileSystemInitializationFailedException {

	public VaultConfigLoadException(String message) {
		super(message);
	}

}
