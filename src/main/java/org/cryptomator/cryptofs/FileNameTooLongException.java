package org.cryptomator.cryptofs;

import java.nio.file.FileSystemException;
import java.nio.file.Path;

/**
 * Indicates that an operation failed, as it would result in a ciphertext path that is too long for the underlying file system.
 *
 * @see org.cryptomator.cryptofs.common.FileSystemCapabilityChecker#determineSupportedFileNameLength(Path) 
 * @since 2.0.0
 */
public class FileNameTooLongException extends FileSystemException {
	
	public FileNameTooLongException(String path, int maxNameLength) {
		super(path, null, "File name or path too long. Max cleartext filename name length is " + maxNameLength);
	}
	
}
