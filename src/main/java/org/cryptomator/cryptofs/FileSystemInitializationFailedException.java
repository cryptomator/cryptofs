package org.cryptomator.cryptofs;

import java.io.IOException;

public class FileSystemInitializationFailedException extends IOException {

	public FileSystemInitializationFailedException(String message, Throwable cause) {
		super(message, cause);
	}

	public FileSystemInitializationFailedException(String message) {
		super(message);
	}
}
