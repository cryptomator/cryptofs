package org.cryptomator.cryptofs.migration.v7;

import com.google.common.io.BaseEncoding;

import java.io.IOException;
import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * Helper class responsible of the migration of a single file
 * <p>
 * Filename migration is a two-step process: Disassembly of the old path and assembly of a new path.
 */
class FilePathMigration {

	private static final Pattern BASE32_PATTERN = Pattern.compile("(0|1[A-Z0-9])?(([A-Z2-7]{8})*[A-Z2-7=]{8})");
	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final BaseEncoding BASE64 = BaseEncoding.base64Url();
	static final int SHORTENING_THRESHOLD = 222; // see calculations in https://github.com/cryptomator/cryptofs/issues/60 

	private final Path oldPath;
	private final String oldCanonicalName;

	/**
	 * @param oldPath The actual file path before migration
	 * @param oldCanonicalName The inflated old filename without any conflicting pre- or suffixes but including the file type prefix
	 */
	FilePathMigration(Path oldPath, String oldCanonicalName) {
		assert BASE32_PATTERN.matcher(oldCanonicalName).matches();
		this.oldPath = oldPath;
		this.oldCanonicalName = oldCanonicalName;
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
		// TODO 3. determine whether any conflict pre- or suffixes exist
		return new FilePathMigration(oldPath, null);
	}

	/**
	 * Migrates the path. This method attempts to give a migrated file its canonical name.
	 * In case of conflicts with existing files a suffix will be added, which will later trigger the conflict resolver.
	 *
	 * @return The path after migrating
	 * @throws IOException Non-recoverable I/O error
	 */
	Path migrate() throws IOException {
		// TODO 4. reencode and add new file extension
		// TODO 5. deflate if exceeding new threshold
		// TODO 6. in case of DIRECTORY or SYMLINK: create parent dir?
		// TODO 7. attempt MOVE, retry with conflict-suffix up to N times in case of FileAlreadyExistsException
		return null;
	}

	/**
	 * @return {@link #oldCanonicalName} without any preceeding "0" or "1S" in case of dirs or symlinks.
	 */
	// visible for testing
	String getOldCanonicalNameWithoutTypePrefix() {
		return null; // TODO
	}

	/**
	 * @return BASE64-encode(BASE32-decode({@link #getOldCanonicalNameWithoutTypePrefix oldCanonicalNameWithoutPrefix})) + ".c9r"
	 */
	// visible for testing
	String getNewInflatedName() {
		return null; // TODO
	}

	/**
	 * @return {@link #getNewInflatedName() newInflatedName} if it is shorter than {@link #SHORTENING_THRESHOLD}, else SHA1(newInflatedName) + ".c9s"
	 */
	// visible for testing
	String getNewDeflatedName() {
		return null; // TODO
	}

	/**
	 * @return <code>true</code> if {@link #oldCanonicalName} starts with "0"
	 */
	// visible for testing
	boolean isDirectory() {
		return false; // TODO
	}

	/**
	 * @return <code>true</code> if {@link #oldCanonicalName} starts with "1S"
	 */
	// visible for testing
	boolean isSymlink() {
		return false; // TODO
	}

}
