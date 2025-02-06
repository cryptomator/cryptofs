package org.cryptomator.cryptofs.dir;

import com.google.common.base.Preconditions;
import com.google.common.io.BaseEncoding;
import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.stream.Stream;

import static org.cryptomator.cryptofs.common.Constants.DIR_FILE_NAME;
import static org.cryptomator.cryptofs.common.Constants.MAX_DIR_ID_LENGTH;
import static org.cryptomator.cryptofs.common.Constants.MAX_SYMLINK_LENGTH;
import static org.cryptomator.cryptofs.common.Constants.SYMLINK_FILE_NAME;

@DirectoryStreamScoped
class C9rConflictResolver {

	private static final Logger LOG = LoggerFactory.getLogger(C9rConflictResolver.class);

	private final Cryptor cryptor;
	private final byte[] dirId;
	private final int maxC9rFileNameLength;
	private final int maxCleartextFileNameLength;

	@Inject
	public C9rConflictResolver(Cryptor cryptor, @Named("dirId") String dirId, VaultConfig vaultConfig) {
		this.cryptor = cryptor;
		this.dirId = dirId.getBytes(StandardCharsets.US_ASCII);
		this.maxC9rFileNameLength = vaultConfig.getShorteningThreshold();
		this.maxCleartextFileNameLength = (maxC9rFileNameLength - 4) / 4 * 3 - 16; // math from FileSystemCapabilityChecker.determineSupportedCleartextFileNameLength()
	}

	public Stream<Node> process(Node node) {
		Preconditions.checkArgument(node.extractedCiphertext != null, "Can only resolve conflicts if extractedCiphertext is set");
		Preconditions.checkArgument(node.cleartextName != null, "Can only resolve conflicts if cleartextName is set");

		String canonicalCiphertextFileName = node.extractedCiphertext + Constants.CRYPTOMATOR_FILE_SUFFIX;
		if (node.fullCiphertextFileName.equals(canonicalCiphertextFileName)) {
			// not a conflict:
			return Stream.of(node);
		} else if (node.fullCiphertextFileName.startsWith(".")) {
			// ignore hidden files:
			LOG.debug("Ignoring hidden file {}", node.ciphertextPath);
			return Stream.empty();
		} else {
			// conflicting file:
			try {
				Path canonicalPath = node.ciphertextPath.resolveSibling(canonicalCiphertextFileName);
				return resolveConflict(node, canonicalPath);
			} catch (IOException e) {
				LOG.error("Failed to resolve conflict for {}", node.ciphertextPath, e);
				return Stream.empty();
			}
		}
	}

	private Stream<Node> resolveConflict(Node conflicting, Path canonicalPath) throws IOException {
		Path conflictingPath = conflicting.ciphertextPath;
		if (resolveConflictTrivially(canonicalPath, conflictingPath)) {
			Node resolved = new Node(canonicalPath);
			resolved.cleartextName = conflicting.cleartextName;
			resolved.extractedCiphertext = conflicting.extractedCiphertext;
			return Stream.of(resolved);
		} else {
			return renameConflictingFile(canonicalPath, conflicting);
		}
	}

	/**
	 * Resolves a conflict by renaming the conflicting file.
	 *
	 * @param canonicalPath The path to the original (conflict-free) file.
	 * @param conflicting The conflicting file.
	 * @return The newly created Node if rename succeeded or an empty stream otherwise.
	 * @throws IOException If an unexpected I/O exception occurs during rename
	 */
	private Stream<Node> renameConflictingFile(Path canonicalPath, Node conflicting) throws IOException {
		assert Files.exists(canonicalPath);
		assert conflicting.fullCiphertextFileName.endsWith(Constants.CRYPTOMATOR_FILE_SUFFIX);
		assert conflicting.fullCiphertextFileName.contains(conflicting.extractedCiphertext);

		final String cleartext = conflicting.cleartextName;
		final int beginOfCleartextExt = cleartext.lastIndexOf('.');
		final String cleartextFileExt = (beginOfCleartextExt > 0) ? cleartext.substring(beginOfCleartextExt) : "";
		final String cleartextBasename = (beginOfCleartextExt > 0) ? cleartext.substring(0, beginOfCleartextExt) : cleartext;

		// let's assume that some the sync conflict string is added at the end of the file name, but before .c9r:
		final int endOfCiphertext = conflicting.fullCiphertextFileName.indexOf(conflicting.extractedCiphertext) + conflicting.extractedCiphertext.length();
		final String originalConflictSuffix = conflicting.fullCiphertextFileName.substring(endOfCiphertext, conflicting.fullCiphertextFileName.length() - Constants.CRYPTOMATOR_FILE_SUFFIX.length());

		// split available maxCleartextFileNameLength between basename, conflict suffix, and file extension:
		final int netCleartext = maxCleartextFileNameLength - cleartextFileExt.length(); // file extension must be preserved
		final String conflictSuffix = originalConflictSuffix.substring(0, Math.min(originalConflictSuffix.length(), netCleartext / 2)); // max 50% of available space
		final int conflictSuffixLen = Math.max(4, conflictSuffix.length()); // prefer to use original conflict suffix, but reserver at least 4 chars for numerical fallback: " (9)"
		final String lengthRestrictedBasename = cleartextBasename.substring(0, Math.min(cleartextBasename.length(), netCleartext - conflictSuffixLen)); // remaining space for basename

		// attempt to use original conflict suffix:
		String alternativeCleartext = lengthRestrictedBasename + conflictSuffix + cleartextFileExt;
		String alternativeCiphertext = cryptor.fileNameCryptor().encryptFilename(BaseEncoding.base64Url(), alternativeCleartext, dirId);
		String alternativeCiphertextName = alternativeCiphertext + Constants.CRYPTOMATOR_FILE_SUFFIX;
		Path alternativePath = canonicalPath.resolveSibling(alternativeCiphertextName);

		// fallback to number conflic suffix, if file with alternative path already exists:
		for (int i = 1; i < 10 && Files.exists(alternativePath); i++) {
			alternativeCleartext = lengthRestrictedBasename + " (" + i + ")" + cleartextFileExt;
			alternativeCiphertext = cryptor.fileNameCryptor().encryptFilename(BaseEncoding.base64Url(), alternativeCleartext, dirId);
			alternativeCiphertextName = alternativeCiphertext + Constants.CRYPTOMATOR_FILE_SUFFIX;
			alternativePath = canonicalPath.resolveSibling(alternativeCiphertextName);
		}

		assert alternativeCiphertextName.length() <= maxC9rFileNameLength;
		try {
			Files.move(conflicting.ciphertextPath, alternativePath, StandardCopyOption.ATOMIC_MOVE);
			LOG.info("Renamed conflicting file {} to {}...", conflicting.ciphertextPath, alternativePath);
			Node node = new Node(alternativePath);
			node.cleartextName = alternativeCleartext;
			node.extractedCiphertext = alternativeCiphertext;
			return Stream.of(node);
		} catch (FileAlreadyExistsException e) {
			// TODO notify user about unresolved conflict: `canonicalPath`
			LOG.warn("Failed to rename conflicting file {} to {}. Keeping original name.", conflicting.ciphertextPath, alternativePath);
			return Stream.empty();
		}
	}


	/**
	 * Tries to resolve a conflicting file without renaming the file. If successful, only the file with the canonical path will exist afterwards.
	 *
	 * @param canonicalPath The path to the original (conflict-free) resource (must not exist).
	 * @param conflictingPath The path to the potentially conflicting file (known to exist).
	 * @return <code>true</code> if the conflict has been resolved.
	 * @throws IOException
	 */
	private boolean resolveConflictTrivially(Path canonicalPath, Path conflictingPath) throws IOException {
		if (!Files.exists(canonicalPath)) {
			Files.move(conflictingPath, canonicalPath); // boom. conflict solved.
			return true;
		} else if (hasSameFileContent(conflictingPath.resolve(DIR_FILE_NAME), canonicalPath.resolve(DIR_FILE_NAME), MAX_DIR_ID_LENGTH)) {
			LOG.info("Removing conflicting directory {} (identical to {})", conflictingPath, canonicalPath);
			MoreFiles.deleteRecursively(conflictingPath, RecursiveDeleteOption.ALLOW_INSECURE);
			return true;
		} else if (hasSameFileContent(conflictingPath.resolve(SYMLINK_FILE_NAME), canonicalPath.resolve(SYMLINK_FILE_NAME), MAX_SYMLINK_LENGTH)) {
			LOG.info("Removing conflicting symlink {} (identical to {})", conflictingPath, canonicalPath);
			MoreFiles.deleteRecursively(conflictingPath, RecursiveDeleteOption.ALLOW_INSECURE);
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @param conflictingPath Path to a potentially conflicting file supposedly containing a directory id
	 * @param canonicalPath Path to the canonical file containing a directory id
	 * @param numBytesToCompare Number of bytes to read from each file and compare to each other.
	 * @return <code>true</code> if the first <code>numBytesToCompare</code> bytes are equal in both files.
	 * @throws IOException If an I/O exception occurs while reading either file.
	 */
	private boolean hasSameFileContent(Path conflictingPath, Path canonicalPath, int numBytesToCompare) throws IOException {
		if (!Files.isDirectory(conflictingPath.getParent()) || !Files.isDirectory(canonicalPath.getParent())) {
			return false;
		}
		try {
			return -1L == Files.mismatch(conflictingPath, canonicalPath);
		} catch (NoSuchFileException e) {
			return false;
		}
	}
}
