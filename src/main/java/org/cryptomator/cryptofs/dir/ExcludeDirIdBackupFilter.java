package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.common.Constants;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;

public class ExcludeDirIdBackupFilter implements DirectoryStream.Filter<Path> {

	@Override
	public boolean accept(Path entry) throws IOException {
		return !entry.equals(entry.resolveSibling(Constants.DIR_BACKUP_FILE_NAME));
	}

}
