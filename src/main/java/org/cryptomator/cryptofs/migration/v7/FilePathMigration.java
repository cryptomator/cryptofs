package org.cryptomator.cryptofs.migration.v7;

import com.google.common.base.Throwables;
import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Helper class responsible of the migration of a single file
 * <p>
 * Filename migration is a two-step process: Disassembly of the old path and assembly of a new path.
 */
class FilePathMigration {

	private static final String OLD_SHORTENED_FILENAME_SUFFIX = ".lng";
	private static final Pattern OLD_SHORTENED_FILENAME_PATTERN = Pattern.compile("[A-Z2-7]{32}");
	private static final Pattern OLD_CANONICAL_FILENAME_PATTERN = Pattern.compile("(0|1S)?([A-Z2-7]{8})*[A-Z2-7=]{8}");
	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final BaseEncoding BASE64 = BaseEncoding.base64Url();
	private static final int SHORTENING_THRESHOLD = 220; // see calculations in https://github.com/cryptomator/cryptofs/issues/60
	private static final String OLD_DIRECTORY_PREFIX = "0";
	private static final String OLD_SYMLINK_PREFIX = "1S";
	private static final String NEW_REGULAR_SUFFIX = ".c9r";
	private static final String NEW_SHORTENED_SUFFIX = ".c9s";
	private static final int MAX_FILENAME_BUFFER_SIZE = 10 * 1024;
	private static final String NEW_SHORTENED_METADATA_FILE = "name.c9s";
	private static final String NEW_DIR_FILE = "dir.c9r";
	private static final String NEW_CONTENTS_FILE = "contents.c9r";
	private static final String NEW_SYMLINK_FILE = "symlink.c9r";

	private final Path oldPath;
	private final String oldCanonicalName;

	/**
	 * @param oldPath          The actual file path before migration
	 * @param oldCanonicalName The inflated old filename without any conflicting pre- or suffixes but including the file type prefix
	 */
	FilePathMigration(Path oldPath, String oldCanonicalName) {
		assert OLD_CANONICAL_FILENAME_PATTERN.matcher(oldCanonicalName).matches();
		this.oldPath = oldPath;
		this.oldCanonicalName = oldCanonicalName;
	}

	/**
	 * Starts a migration of the given file.
	 *
	 * @param vaultRoot Path to the vault's base directory (parent of <code>d/</code> and <code>m/</code>).
	 * @param oldPath   Path of an existing file inside the <code>d/</code> directory of a vault. May be a normal file, directory file or symlink as well as conflicting copies.
	 * @return A new instance of FileNameMigration
	 * @throws IOException Non-recoverable I/O error, such as {@link UninflatableFileException}s
	 */
	public static Optional<FilePathMigration> parse(Path vaultRoot, Path oldPath) throws IOException {
		final String oldFileName = oldPath.getFileName().toString();
		final String canonicalOldFileName;
		if (oldFileName.endsWith(NEW_REGULAR_SUFFIX) || oldFileName.endsWith(NEW_SHORTENED_SUFFIX)) {
			// make sure to not match already migrated files
			// (since BASE32 is a subset of BASE64, pure pattern matching could accidentally match those)
			return Optional.empty();
		} else if (oldFileName.endsWith(OLD_SHORTENED_FILENAME_SUFFIX)) {
			Matcher matcher = OLD_SHORTENED_FILENAME_PATTERN.matcher(oldFileName);
			if (matcher.find()) {
				canonicalOldFileName = inflate(vaultRoot, matcher.group() + OLD_SHORTENED_FILENAME_SUFFIX);
			} else {
				return Optional.empty();
			}
		} else {
			Matcher matcher = OLD_CANONICAL_FILENAME_PATTERN.matcher(oldFileName);
			if (matcher.find()) {
				canonicalOldFileName = matcher.group();
			} else {
				return Optional.empty();
			}
		}
		return Optional.of(new FilePathMigration(oldPath, canonicalOldFileName));
	}

	/**
	 * Resolves the canonical name of a deflated file represented by the given <code>longFileName</code>.
	 *
	 * @param vaultRoot    Path to the vault's base directory (parent of <code>d/</code> and <code>m/</code>).
	 * @param longFileName Canonical name of the {@value #OLD_SHORTENED_FILENAME_SUFFIX} file.
	 * @return The inflated filename
	 * @throws UninflatableFileException If the file could not be inflated due to missing or malformed metadata.
	 */
	// visible for testing
	static String inflate(Path vaultRoot, String longFileName) throws UninflatableFileException {
		Path metadataFilePath = vaultRoot.resolve("m/" + longFileName.substring(0, 2) + "/" + longFileName.substring(2, 4) + "/" + longFileName);
		try (SeekableByteChannel ch = Files.newByteChannel(metadataFilePath, StandardOpenOption.READ)) {
			if (ch.size() > MAX_FILENAME_BUFFER_SIZE) {
				throw new UninflatableFileException("Unexpectedly large file: " + metadataFilePath);
			}
			ByteBuffer buf = ByteBuffer.allocate((int) Math.min(ch.size(), MAX_FILENAME_BUFFER_SIZE));
			ch.read(buf);
			buf.flip();
			return UTF_8.decode(buf).toString();
		} catch (IOException e) {
			Throwables.throwIfInstanceOf(e, UninflatableFileException.class);
			throw new UninflatableFileException("Failed to read metadata file " + metadataFilePath, e);
		}
	}

	/**
	 * Migrates the path. This method attempts to give a migrated file its canonical name.
	 * In case of conflicts with existing files a suffix will be added, which will later trigger the conflict resolver.
	 *
	 * @return The path after migrating
	 * @throws IOException Non-recoverable I/O error
	 */
	public Path migrate() throws IOException {
		final String canonicalInflatedName = getNewInflatedName();
		final String canonicalDeflatedName = getNewDeflatedName();
		final boolean isShortened = !canonicalInflatedName.equals(canonicalDeflatedName);

		FileAlreadyExistsException attemptsExceeded = new FileAlreadyExistsException(oldPath.toString(), oldPath.resolveSibling(canonicalDeflatedName).toString(), "");
		String attemptSuffix = "";

		for (int i = 1; i <= 3; i++) {
			try {
				Path newPath = getTargetPath(attemptSuffix);
				if (isShortened || isDirectory() || isSymlink()) {
					Files.createDirectory(newPath.getParent());
				}
				if (isShortened) {
					Path metadataFilePath = newPath.resolveSibling(NEW_SHORTENED_METADATA_FILE);
					Files.write(metadataFilePath, canonicalInflatedName.getBytes(UTF_8));
				}
				return Files.move(oldPath, newPath);
			} catch (FileAlreadyExistsException e) {
				attemptSuffix = "_" + i;
				attemptsExceeded.addSuppressed(e);
				continue;
			}
		}
		throw attemptsExceeded;
	}

	/**
	 * @param attemptSuffix Empty string or anything starting with a non base64 delimiter
	 * @return The path after successful migration of {@link #oldPath} if migration is successful for the given attemptSuffix
	 */
	Path getTargetPath(String attemptSuffix) throws InvalidOldFilenameException {
		final String canonicalInflatedName = getNewInflatedName();
		final String canonicalDeflatedName = getNewDeflatedName();
		final boolean isShortened = !canonicalInflatedName.equals(canonicalDeflatedName);

		final String inflatedName = canonicalInflatedName.substring(0, canonicalInflatedName.length() - NEW_REGULAR_SUFFIX.length()) + attemptSuffix + NEW_REGULAR_SUFFIX;
		final String deflatedName = canonicalDeflatedName.substring(0, canonicalDeflatedName.length() - NEW_SHORTENED_SUFFIX.length()) + attemptSuffix + NEW_SHORTENED_SUFFIX;

		if (isShortened) {
			if (isDirectory()) {
				return oldPath.resolveSibling(deflatedName).resolve(NEW_DIR_FILE);
			} else if (isSymlink()) {
				return oldPath.resolveSibling(deflatedName).resolve(NEW_SYMLINK_FILE);
			} else {
				return oldPath.resolveSibling(deflatedName).resolve(NEW_CONTENTS_FILE);
			}
		} else {
			if (isDirectory()) {
				return oldPath.resolveSibling(inflatedName).resolve(NEW_DIR_FILE);
			} else if (isSymlink()) {
				return oldPath.resolveSibling(inflatedName).resolve(NEW_SYMLINK_FILE);
			} else {
				return oldPath.resolveSibling(inflatedName);
			}
		}
	}

	public Path getOldPath() {
		return oldPath;
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
	 * @return BASE64-encode({@link #getDecodedCiphertext oldDecodedCiphertext}) + {@value #NEW_REGULAR_SUFFIX}
	 * @throws InvalidOldFilenameException if failing to base32-decode the old filename
	 */
	// visible for testing
	String getNewInflatedName() throws InvalidOldFilenameException {
		byte[] decoded = getDecodedCiphertext();
		return BASE64.encode(decoded) + NEW_REGULAR_SUFFIX;
	}

	/**
	 * @return BASE32-decode({@link #getOldCanonicalNameWithoutTypePrefix oldCanonicalNameWithoutPrefix})
	 * @throws InvalidOldFilenameException if failing to base32-decode the old filename
	 */
	// visible for testing
	byte[] getDecodedCiphertext() throws InvalidOldFilenameException {
		String encodedCiphertext = getOldCanonicalNameWithoutTypePrefix();
		try {
			return BASE32.decode(encodedCiphertext);
		} catch (IllegalArgumentException e) {
			throw new InvalidOldFilenameException("Can't base32-decode '" + encodedCiphertext + "' in file " + oldPath.toString(), e);
		}
	}

	/**
	 * @return {@link #getNewInflatedName() newInflatedName} if it is shorter than {@link #SHORTENING_THRESHOLD}, else BASE64(SHA1(newInflatedName)) + ".c9s"
	 */
	// visible for testing
	String getNewDeflatedName() throws InvalidOldFilenameException {
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
