package org.cryptomator.cryptofs;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cryptomator.cryptofs.Constants.SHORT_NAMES_MAX_LENGTH;
import static org.cryptomator.cryptofs.LongFileNameProvider.LONG_NAME_FILE_EXT;

@CryptoFileSystemScoped
class ConflictResolver {

	private static final Logger LOG = LoggerFactory.getLogger(ConflictResolver.class);
	private static final Pattern CIPHERTEXT_FILENAME_PATTERN = Pattern.compile("(0|1[A-Z0-9])?([A-Z2-7]{8})*[A-Z2-7=]{8}");
	private static final int MAX_DIR_FILE_SIZE = 87; // "normal" file header has 88 bytes

	private final LongFileNameProvider longFileNameProvider;
	private final Cryptor cryptor;

	@Inject
	public ConflictResolver(LongFileNameProvider longFileNameProvider, Cryptor cryptor) {
		this.longFileNameProvider = longFileNameProvider;
		this.cryptor = cryptor;
	}

	/**
	 * Checks if the name of the file represented by the given ciphertextPath is a valid ciphertext name without any additional chars.
	 * If any unexpected chars are found on the name but it still contains an authentic ciphertext, it is considered a conflicting file.
	 * Conflicting files will be given a new name. The caller must use the path returned by this function after invoking it, as the given ciphertextPath might be no longer valid.
	 * 
	 * @param ciphertextPath The path to a file to check.
	 * @param dirId The directory id of the file's parent directory.
	 * @return Either the original name if no unexpected chars have been found or a completely new path.
	 * @throws IOException
	 */
	public Path resolveConflictsIfNecessary(Path ciphertextPath, String dirId) throws IOException {
		String ciphertextFileName = ciphertextPath.getFileName().toString();
		String basename = StringUtils.removeEnd(ciphertextFileName, LONG_NAME_FILE_EXT);
		Matcher m = CIPHERTEXT_FILENAME_PATTERN.matcher(basename);
		if (!m.matches() && m.find(0)) {
			// no full match, but still contains base32 -> partial match
			return resolveConflict(ciphertextPath, m.group(0), dirId);
		} else {
			// full match or no match at all -> nothing to resolve
			return ciphertextPath;
		}
	}

	/**
	 * Resolves a conflict.
	 * 
	 * @param conflictingPath The path of a file containing a valid base 32 part.
	 * @param ciphertextFileName The base32 part inside the filename of the conflicting file.
	 * @param dirId The directory id of the file's parent directory.
	 * @return The new path of the conflicting file after the conflict has been resolved.
	 * @throws IOException
	 */
	private Path resolveConflict(Path conflictingPath, String ciphertextFileName, String dirId) throws IOException {
		String conflictingFileName = conflictingPath.getFileName().toString();
		Preconditions.checkArgument(conflictingFileName.contains(ciphertextFileName), "%s does not contain %s", conflictingPath, ciphertextFileName);

		Path parent = conflictingPath.getParent();
		String inflatedFileName;
		Path canonicalPath;
		if (longFileNameProvider.isDeflated(conflictingFileName)) {
			String deflatedName = ciphertextFileName + LONG_NAME_FILE_EXT;
			inflatedFileName = longFileNameProvider.inflate(deflatedName);
			canonicalPath = parent.resolve(deflatedName);
		} else {
			inflatedFileName = ciphertextFileName;
			canonicalPath = parent.resolve(ciphertextFileName);
		}

		CiphertextFileType type = CiphertextFileType.forFileName(inflatedFileName);
		assert inflatedFileName.startsWith(type.getPrefix());
		String ciphertext = inflatedFileName.substring(type.getPrefix().length());

		if (CiphertextFileType.DIRECTORY.equals(type) && resolveDirectoryConflictTrivially(canonicalPath, conflictingPath)) {
			return canonicalPath;
		} else {
			return renameConflictingFile(canonicalPath, conflictingPath, ciphertext, dirId, type.getPrefix());
		}
	}

	/**
	 * Resolves a conflict by renaming the conflicting file.
	 * 
	 * @param canonicalPath The path to the original (conflict-free) file.
	 * @param conflictingPath The path to the potentially conflicting file.
	 * @param ciphertext The (previously inflated) ciphertext name of the file without any preceeding directory prefix.
	 * @param dirId The directory id of the file's parent directory.
	 * @param dirPrefix The directory prefix (if the conflicting file is a directory file) or an empty string.
	 * @return The new path after renaming the conflicting file.
	 * @throws IOException
	 */
	private Path renameConflictingFile(Path canonicalPath, Path conflictingPath, String ciphertext, String dirId, String dirPrefix) throws IOException {
		try {
			String cleartext = cryptor.fileNameCryptor().decryptFilename(ciphertext, dirId.getBytes(StandardCharsets.UTF_8));
			Path alternativePath = canonicalPath;
			for (int i = 1; Files.exists(alternativePath); i++) {
				String alternativeCleartext = cleartext + " (Conflict " + i + ")";
				String alternativeCiphertext = cryptor.fileNameCryptor().encryptFilename(alternativeCleartext, dirId.getBytes(StandardCharsets.UTF_8));
				String alternativeCiphertextFileName = dirPrefix + alternativeCiphertext;
				if (alternativeCiphertextFileName.length() > SHORT_NAMES_MAX_LENGTH) {
					alternativeCiphertextFileName = longFileNameProvider.deflate(alternativeCiphertextFileName);
				}
				alternativePath = canonicalPath.resolveSibling(alternativeCiphertextFileName);
			}
			LOG.info("Moving conflicting file {} to {}", conflictingPath, alternativePath);
			Path resolved = Files.move(conflictingPath, alternativePath, StandardCopyOption.ATOMIC_MOVE);
			longFileNameProvider.getCached(resolved).ifPresent(LongFileNameProvider.DeflatedFileName::persist);
			return resolved;
		} catch (AuthenticationFailedException e) {
			// not decryptable, no need to resolve any kind of conflict
			LOG.info("Found valid Base32 string, which is an unauthentic ciphertext: {}", conflictingPath);
			return conflictingPath;
		}
	}

	/**
	 * Tries to resolve a conflicting directory file without renaming the file. If successful, only the file with the canonical path will exist afterwards.
	 * 
	 * @param canonicalPath The path to the original (conflict-free) directory file (must not exist).
	 * @param conflictingPath The path to the potentially conflicting file (known to exist).
	 * @return <code>true</code> if the conflict has been resolved.
	 * @throws IOException
	 */
	private boolean resolveDirectoryConflictTrivially(Path canonicalPath, Path conflictingPath) throws IOException {
		if (!Files.exists(canonicalPath)) {
			Files.move(conflictingPath, canonicalPath, StandardCopyOption.ATOMIC_MOVE);
			return true;
		} else if (hasSameDirFileContent(conflictingPath, canonicalPath)) {
			// there must not be two directories pointing to the same dirId.
			LOG.info("Removing conflicting directory file {} (identical to {})", conflictingPath, canonicalPath);
			Files.deleteIfExists(conflictingPath);
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @param conflictingPath Path to a potentially conflicting file supposedly containing a directory id
	 * @param canonicalPath Path to the canonical file containing a directory id
	 * @return <code>true</code> if the first {@value #MAX_DIR_FILE_SIZE} bytes are equal in both files.
	 * @throws IOException If an I/O exception occurs while reading either file.
	 */
	private boolean hasSameDirFileContent(Path conflictingPath, Path canonicalPath) throws IOException {
		try (ReadableByteChannel in1 = Files.newByteChannel(conflictingPath, StandardOpenOption.READ); //
				ReadableByteChannel in2 = Files.newByteChannel(canonicalPath, StandardOpenOption.READ)) {
			ByteBuffer buf1 = ByteBuffer.allocate(MAX_DIR_FILE_SIZE);
			ByteBuffer buf2 = ByteBuffer.allocate(MAX_DIR_FILE_SIZE);
			int read1 = in1.read(buf1);
			int read2 = in2.read(buf2);
			buf1.flip();
			buf2.flip();
			return read1 == read2 && buf1.compareTo(buf2) == 0;
		}
	}

}
