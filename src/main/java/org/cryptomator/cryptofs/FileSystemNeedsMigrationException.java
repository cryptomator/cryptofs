package org.cryptomator.cryptofs;

import java.nio.file.FileSystemException;
import java.nio.file.Path;

import org.cryptomator.cryptofs.migration.Migrators;

/**
 * Indicates that no file system for a given vault can be created, because the vault has been created with an older version of this library.
 * 
 * @see Migrators
 * @since 1.4.0
 */
public class FileSystemNeedsMigrationException extends FileSystemException {

	public FileSystemNeedsMigrationException(Path pathToVault) {
		super(pathToVault.toString(), null, "File system needs migration to a newer format.");
	}

}
