package org.cryptomator.cryptofs;

public class VaultVersionMismatchException extends VaultConfigLoadException {

	public VaultVersionMismatchException(String message) {
		super(message);
	}

}
