package org.cryptomator.cryptofs.common;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class FileUtil {

	private FileUtil() {};

	public static byte[] readAllBytesSizeRestricted(Path target, int maxSize) throws IOException {
		long size = Files.size(target);
		if (size > maxSize) {
			throw new FileTooBigException(target, size, maxSize);
		}
		return Files.readAllBytes(target);
	}

}
