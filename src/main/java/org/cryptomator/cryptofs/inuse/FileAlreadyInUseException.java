package org.cryptomator.cryptofs.inuse;

import java.nio.file.FileSystemException;
import java.nio.file.Path;

public class FileAlreadyInUseException extends FileSystemException {

	public FileAlreadyInUseException(Path path) {
		super(path.toString());
	}
}
