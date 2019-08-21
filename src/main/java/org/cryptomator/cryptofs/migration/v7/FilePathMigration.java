package org.cryptomator.cryptofs.migration.v7;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;

import java.io.IOException;
import java.nio.file.Path;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Helper class responsible of the migration of a single file
 * <p>
 * Filename migration is a two-step process: Disassembly of the old path and assembly of a new path.
 */
class FilePathMigration {

	private static final Pattern BASE32_PATTERN = Pattern.compile("(0|1[A-Z0-9])?(([A-Z2-7]{8})*[A-Z2-7=]{8})");
	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final BaseEncoding BASE64 = BaseEncoding.base64Url();
	private static final int SHORTENING_THRESHOLD = 222; // see calculations in https://github.com/cryptomator/cryptofs/issues/60
	private static final String OLD_DIRECTORY_PREFIX = "0";
	private static final String OLD_SYMLINK_PREFIX = "1S";
	private static final String NEW_REGULAR_SUFFIX = ".c9r";
	private static final String NEW_SHORTENED_SUFFIX = ".c9s";

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
	
	// visible for testing
	String getOldCanonicalName() {
		return oldCanonicalName;
	}

	/**
	 * @return {@link #oldCanonicalName} without any preceeding "0" or "1S" in case of dirs or symlinks.
	 */
	// visible for testing
	String getOldCanonicalNameWithoutTypePrefix() {
		if (oldCanonicalName.startsWith(OLD_DIRECTORY_PREFIX)) {
			return oldCanonicalName.substring(OLD_DIRECTORY_PREFIX.length());
		} else if (oldCanonicalName.startsWith(OLD_SYMLINK_PREFIX)) {
			return oldCanonicalName.substring(OLD_SYMLINK_PREFIX.length());
		} else {
			return oldCanonicalName;
		}
	}

	/**
	 * @return BASE64-encode(BASE32-decode({@link #getOldCanonicalNameWithoutTypePrefix oldCanonicalNameWithoutPrefix})) + {@value #NEW_REGULAR_SUFFIX}
	 */
	// visible for testing
	String getNewInflatedName() {
		byte[] decoded = BASE32.decode(getOldCanonicalNameWithoutTypePrefix());
		return BASE64.encode(decoded) + NEW_REGULAR_SUFFIX;
	}

	/**
	 * @return {@link #getNewInflatedName() newInflatedName} if it is shorter than {@link #SHORTENING_THRESHOLD}, else BASE64(SHA1(newInflatedName)) + ".c9s"
	 */
	// visible for testing
	String getNewDeflatedName() {
		String inflatedName = getNewInflatedName();
		if (inflatedName.length() > SHORTENING_THRESHOLD) {
			byte[] longFileNameBytes = inflatedName.getBytes(UTF_8);
			byte[] hash = MessageDigestSupplier.SHA1.get().digest(longFileNameBytes);
			return BASE64.encode(hash) + NEW_SHORTENED_SUFFIX;
		} else {
			return inflatedName;
		}
	}

	/**
	 * @return <code>true</code> if {@link #oldCanonicalName} starts with "0"
	 */
	// visible for testing
	boolean isDirectory() {
		return oldCanonicalName.startsWith(OLD_DIRECTORY_PREFIX);
	}

	/**
	 * @return <code>true</code> if {@link #oldCanonicalName} starts with "1S"
	 */
	// visible for testing
	boolean isSymlink() {
		return oldCanonicalName.startsWith(OLD_SYMLINK_PREFIX);
	}

}
