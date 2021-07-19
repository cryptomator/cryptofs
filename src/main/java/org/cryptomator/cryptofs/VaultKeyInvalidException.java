package org.cryptomator.cryptofs;

/**
 * An attempt was made to verify the signature of a vault config token using an invalid key.
 */
public class VaultKeyInvalidException extends VaultConfigLoadException {

	public VaultKeyInvalidException() {
		super("Failed to verify vault config signature using the provided key.");
	}

}
