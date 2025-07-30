package org.cryptomator.cryptofs.fh;

import java.nio.file.FileSystemException;
import java.nio.file.Path;

public class FileIsInUseException extends FileSystemException {

	public FileIsInUseException(Path path) {
		super(path.toString());
	}
}
