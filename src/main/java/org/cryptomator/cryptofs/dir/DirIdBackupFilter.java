package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.common.Constants;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;

public class DirIdBackupFilter implements DirectoryStream.Filter<Path> {

	private final Path skippedEntry = Path.of(Constants.DIR_BACKUP_FILE_NAME);

	@Override
	public boolean accept(Path entry) throws IOException {
		return entry.getFileName().equals(skippedEntry);
	}

}
