package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;

import javax.inject.Inject;

/**
 * Mockable wrapper around {@link Files} operations.
 * 
 * @author Markus Kreusch
 */
@PerProvider
class FilesWrapper {

	@Inject
	public FilesWrapper() {
	}

	public Path createDirectories(Path dir, FileAttribute<?>... attrs) throws IOException {
		return Files.createDirectories(dir, attrs);
	}

}
