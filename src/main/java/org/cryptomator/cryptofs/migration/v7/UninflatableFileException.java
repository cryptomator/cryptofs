package org.cryptomator.cryptofs.migration.v7;

import java.io.IOException;

public class UninflatableFileException extends IOException {

	public UninflatableFileException(String message) {
		super(message);
	}

	public UninflatableFileException(String message, Throwable cause) {
		super(message, cause);
	}
}
