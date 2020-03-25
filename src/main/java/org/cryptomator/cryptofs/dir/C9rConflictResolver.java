package org.cryptomator.cryptofs.dir;

import com.google.common.base.Preconditions;
import com.google.common.io.BaseEncoding;
import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.stream.Stream;

import static org.cryptomator.cryptofs.common.Constants.DIR_FILE_NAME;
import static org.cryptomator.cryptofs.common.Constants.MAX_CIPHERTEXT_NAME_LENGTH;
import static org.cryptomator.cryptofs.common.Constants.MAX_CLEARTEXT_NAME_LENGTH;
import static org.cryptomator.cryptofs.common.Constants.MAX_DIR_FILE_LENGTH;
import static org.cryptomator.cryptofs.common.Constants.MAX_SYMLINK_LENGTH;
import static org.cryptomator.cryptofs.common.Constants.SYMLINK_FILE_NAME;

@DirectoryStreamScoped
class C9rConflictResolver {

	private static final Logger LOG = LoggerFactory.getLogger(C9rConflictResolver.class);

	private final Cryptor cryptor;
	private final byte[] dirId;

	@Inject
	public C9rConflictResolver(Cryptor cryptor, @Named("dirId") String dirId) {
		this.cryptor = cryptor;
		this.dirId = dirId.getBytes(StandardCharsets.US_ASCII);
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
				LOG.error("Failed to resolve conflict for " + node.ciphertextPath, e);
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
			return Stream.of(renameConflictingFile(canonicalPath, conflictingPath, conflicting.cleartextName));
		}
	}

	/**
	 * Resolves a conflict by renaming the conflicting file.
	 *
	 * @param canonicalPath   The path to the original (conflict-free) file.
	 * @param conflictingPath The path to the potentially conflicting file.
	 * @param cleartext       The cleartext name of the conflicting file.
	 * @return The newly created Node after renaming the conflicting file.
	 * @throws IOException
	 */
	private Node renameConflictingFile(Path canonicalPath, Path conflictingPath, String cleartext) throws IOException {
		assert Files.exists(canonicalPath);
		final int beginOfFileExtension = cleartext.lastIndexOf('.');
		final String fileExtension = (beginOfFileExtension > 0) ? cleartext.substring(beginOfFileExtension) : "";
		final String basename = (beginOfFileExtension > 0) ? cleartext.substring(0, beginOfFileExtension) : cleartext;
		final String lengthRestrictedBasename = basename.substring(0, Math.min(basename.length(), MAX_CLEARTEXT_NAME_LENGTH - fileExtension.length() - 5)); // 5 chars for conflict suffix " (42)"
		String alternativeCleartext;
		String alternativeCiphertext;
		String alternativeCiphertextName;
		Path alternativePath;
		int i = 1;
		do {
			alternativeCleartext = lengthRestrictedBasename + " (" + i++ + ")" + fileExtension;
			alternativeCiphertext = cryptor.fileNameCryptor().encryptFilename(BaseEncoding.base64Url(), alternativeCleartext, dirId);
			alternativeCiphertextName = alternativeCiphertext + Constants.CRYPTOMATOR_FILE_SUFFIX;
			alternativePath = canonicalPath.resolveSibling(alternativeCiphertextName);
		} while (Files.exists(alternativePath));
		assert alternativeCiphertextName.length() <= MAX_CIPHERTEXT_NAME_LENGTH;
		LOG.info("Moving conflicting file {} to {}", conflictingPath, alternativePath);
		Files.move(conflictingPath, alternativePath, StandardCopyOption.ATOMIC_MOVE);
		Node node = new Node(alternativePath);
		node.cleartextName = alternativeCleartext;
		node.extractedCiphertext = alternativeCiphertext;
		return node;
	}


	/**
	 * Tries to resolve a conflicting file without renaming the file. If successful, only the file with the canonical path will exist afterwards.
	 *
	 * @param canonicalPath   The path to the original (conflict-free) resource (must not exist).
	 * @param conflictingPath The path to the potentially conflicting file (known to exist).
	 * @return <code>true</code> if the conflict has been resolved.
	 * @throws IOException
	 */
	private boolean resolveConflictTrivially(Path canonicalPath, Path conflictingPath) throws IOException {
		if (!Files.exists(canonicalPath)) {
			Files.move(conflictingPath, canonicalPath); // boom. conflict solved.
			return true;
		} else if (hasSameFileContent(conflictingPath.resolve(DIR_FILE_NAME), canonicalPath.resolve(DIR_FILE_NAME), MAX_DIR_FILE_LENGTH)) {
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
	 * @param conflictingPath   Path to a potentially conflicting file supposedly containing a directory id
	 * @param canonicalPath     Path to the canonical file containing a directory id
	 * @param numBytesToCompare Number of bytes to read from each file and compare to each other.
	 * @return <code>true</code> if the first <code>numBytesToCompare</code> bytes are equal in both files.
	 * @throws IOException If an I/O exception occurs while reading either file.
	 */
	private boolean hasSameFileContent(Path conflictingPath, Path canonicalPath, int numBytesToCompare) throws IOException {
		if (!Files.isDirectory(conflictingPath.getParent()) || !Files.isDirectory(canonicalPath.getParent())) {
			return false;
		}
		try (ReadableByteChannel in1 = Files.newByteChannel(conflictingPath, StandardOpenOption.READ); //
			 ReadableByteChannel in2 = Files.newByteChannel(canonicalPath, StandardOpenOption.READ)) {
			ByteBuffer buf1 = ByteBuffer.allocate(numBytesToCompare);
			ByteBuffer buf2 = ByteBuffer.allocate(numBytesToCompare);
			int read1 = in1.read(buf1);
			int read2 = in2.read(buf2);
			buf1.flip();
			buf2.flip();
			return read1 == read2 && buf1.compareTo(buf2) == 0;
		} catch (NoSuchFileException e) {
			return false;
		}
	}
}
