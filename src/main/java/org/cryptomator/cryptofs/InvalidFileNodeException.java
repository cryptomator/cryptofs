package org.cryptomator.cryptofs;

import java.nio.file.FileSystemException;

/**
 * Exception thrown if a c9s or c9r directory does not contain any identification files
 */
public class InvalidFileNodeException extends FileSystemException {

	public InvalidFileNodeException(String cleartext, String ciphertext) {
		super(cleartext, null, "Unknown type of node %s: Missing identification file".formatted(ciphertext));
	}
}
