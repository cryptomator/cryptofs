package org.cryptomator.cryptofs.migration.v7;

import java.io.IOException;

public class InvalidOldFilenameException extends IOException {
	
	public InvalidOldFilenameException(String message, Throwable cause) {
		super(message, cause);
	}
}