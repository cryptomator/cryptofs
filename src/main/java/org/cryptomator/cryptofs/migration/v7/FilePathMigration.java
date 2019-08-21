package org.cryptomator.cryptofs.migration.v7;

import com.google.common.io.BaseEncoding;

import java.io.IOException;
import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * Helper class responsible of the migration of a single file
 */
class FilePathMigration {

	private static final Pattern BASE32_PATTERN = Pattern.compile("(0|1[A-Z0-9])?(([A-Z2-7]{8})*[A-Z2-7=]{8})");
	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final BaseEncoding BASE64 = BaseEncoding.base64Url();

	private final Path oldPath;
	private final String oldCanonicalName;
	private final String oldFileTypePrefix;

	private FilePathMigration(Path oldPath, String oldCanonicalName, String oldFileTypePrefix) {
		this.oldPath = oldPath;
		this.oldCanonicalName = oldCanonicalName;
		this.oldFileTypePrefix = oldFileTypePrefix;
	}

	/**
	 * Starts a migration of the given file.
	 *
	 * @param vaultRoot Path to the vault's base directory (parent of <code>d/</code> and <code>m/</code>).
	 * @param oldPath   Path of an existing file inside the <code>d/</code> directory of a vault. May be a normal file, directory file or symlink as well as conflicting copies.
	 * @return A new instance of FileNameMigration
	 * @throws IOException Non-recoverable I/O error, e.g. if a .lng file could not be inflated due to missing metadata.
	 */
	static FilePathMigration parse(Path vaultRoot, Path oldPath) throws IOException {
		// TODO 1. extract canonical name
		// TODO 2. inflate
		// TODO 3. determine whether DIRECTORY or SYMLINK
		// TODO 4. determine whether any conflict pre- or suffixes exist
		return new FilePathMigration(oldPath, null, null);
	}

	/**
	 * @return The path after migrating
	 * @throws IOException Non-recoverable I/O error
	 */
	Path migrate() throws IOException {
		// TODO 5. reencode and add new file extension
		// TODO 6. deflate if exceeding new threshold
		// TODO 7. in case of DIRECTORY or SYMLINK: create parent dir?
		// TODO 8. attempt MOVE, retry with conflict-suffix up to N times in case of FileAlreadyExistsException
		return null;
	}
	
}
