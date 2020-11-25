package org.cryptomator.cryptofs;

import java.io.IOException;

/**
 * Thrown by a {@link KeyLoader} when loading a key required to unlock a vault failed.
 * <p>
 * Possible reasons for this exception are: Unsupported key type, key for given id not found, user cancelled key entry, ...
 */
public class KeyLoadingFailedException extends FileSystemInitializationFailedException {

	public KeyLoadingFailedException(String message, Throwable cause) {
		super(message, cause);
	}
}
