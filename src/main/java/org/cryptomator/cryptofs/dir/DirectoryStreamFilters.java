package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.common.Constants;

import java.nio.file.DirectoryStream;
import java.nio.file.Path;

public interface DirectoryStreamFilters {

	static DirectoryStream.Filter<Path> EXCLUDE_DIR_ID_BACKUP = p -> !p.equals(p.resolveSibling(Constants.DIR_BACKUP_FILE_NAME));

}
