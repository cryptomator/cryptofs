package org.cryptomator.cryptofs;

import java.nio.file.FileSystemException;
import java.nio.file.Path;

/**
 * Indicates that an operation failed, as it would result in a ciphertext path that is too long for the underlying file system.
 *
 * @see org.cryptomator.cryptofs.common.FileSystemCapabilityChecker#determineSupportedFileNameLength(Path) 
 * @since 1.9.8
 */
public class FileNameTooLongException extends FileSystemException {
	
	public FileNameTooLongException(String c9rPathRelativeToVaultRoot, int maxPathLength, int maxNameLength) {
		super(c9rPathRelativeToVaultRoot, null, "File name or path too long. Max ciphertext path name length is " + maxPathLength + ". Max ciphertext name is " + maxNameLength);
	}
	
}
