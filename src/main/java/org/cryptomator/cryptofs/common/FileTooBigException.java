package org.cryptomator.cryptofs.common;

import java.io.IOException;
import java.nio.file.Path;

public class FileTooBigException extends IOException {

	public FileTooBigException(Path file, long currentSize, int maxSize) {
		super("File %s has size %d, exceeding maximum allowed size of %d.".formatted(file, currentSize, maxSize));
	}

}
