package org.cryptomator.cryptofs.dir;

import com.google.common.io.BaseEncoding;
import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import org.cryptomator.cryptofs.CiphertextFilePath;
import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.LongFileNameProvider;
import org.cryptomator.cryptofs.common.StringUtils;
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
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cryptomator.cryptofs.common.Constants.CRYPTOMATOR_FILE_SUFFIX;
import static org.cryptomator.cryptofs.common.Constants.DEFLATED_FILE_SUFFIX;
import static org.cryptomator.cryptofs.common.Constants.DIR_FILE_NAME;
import static org.cryptomator.cryptofs.common.Constants.MAX_SYMLINK_LENGTH;
import static org.cryptomator.cryptofs.common.Constants.SYMLINK_FILE_NAME;

@CryptoFileSystemScoped
class ConflictResolver {

	private static final Logger LOG = LoggerFactory.getLogger(ConflictResolver.class);
	private static final Pattern BASE64_PATTERN = Pattern.compile("([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_=]{4}");
	private static final int MAX_DIR_FILE_SIZE = 87; // "normal" file header has 88 bytes

	private final LongFileNameProvider longFileNameProvider;
	private final CryptoPathMapper cryptoPathMapper;
	private final Cryptor cryptor;

	@Inject
	public ConflictResolver(LongFileNameProvider longFileNameProvider, CryptoPathMapper cryptoPathMapper, Cryptor cryptor) {
		this.longFileNameProvider = longFileNameProvider;
		this.cryptoPathMapper = cryptoPathMapper;
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
		
		final String basename;
		final String extension;
		if (ciphertextFileName.endsWith(DEFLATED_FILE_SUFFIX)) {
			basename = StringUtils.removeEnd(ciphertextFileName, DEFLATED_FILE_SUFFIX);
			extension = DEFLATED_FILE_SUFFIX;
		} else if (ciphertextFileName.endsWith(CRYPTOMATOR_FILE_SUFFIX)) {
			basename = StringUtils.removeEnd(ciphertextFileName, CRYPTOMATOR_FILE_SUFFIX);
			extension = CRYPTOMATOR_FILE_SUFFIX;
		} else {
			// file doesn't belong to the vault structure -> nothing to resolve
			return ciphertextPath;
		}
		
		Matcher m = BASE64_PATTERN.matcher(basename);
		if (!m.matches() && m.find(0)) {
			// no full match, but still contains base64 -> partial match
			Path canonicalPath = ciphertextPath.resolveSibling(m.group() + extension);
			return resolveConflict(ciphertextPath, canonicalPath, dirId);
		} else {
			// full match or no match at all -> nothing to resolve
			return ciphertextPath;
		}
	}

	//private static final Pattern BASE64_PATTERN = Pattern.compile("([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_]{20}[a-zA-Z0-9-_=]{4}");
	//private static final Pattern DELIM_PATTERN = Pattern.compile("[!a-zA-Z0-9]");
//	public String extractCiphertext(String potentialCiphertext, byte[] dirIdBytes) {
//		// attempt a full match:
//		Matcher m = BASE64_PATTERN.matcher(potentialCiphertext);
//		if (m.matches()) {
//			try {
//				String cleartext = cryptor.fileNameCryptor().decryptFilename(BaseEncoding.base64Url(), potentialCiphertext, dirIdBytes);
//				return potentialCiphertext;
//			} catch (AuthenticationFailedException e) {
//				// proceed with partial matches
//			}
//		}
//		
//		// strip potential prefix:
//		Matcher d = DELIM_PATTERN.matcher(potentialCiphertext);
//		if (d.find()) {
//			int endOfPrefix = d.end();
//			assert endOfPrefix > 0;
//			return extractCiphertext(potentialCiphertext.substring(endOfPrefix), dirIdBytes);
//		}
//		
//		// strip potential suffix:
//		int beginOfSuffix = 0;
//		while (d.find(beginOfSuffix)) { // we can only loop through matches from begin to end to find the last match
//			beginOfSuffix = d.start();
//		}
//		if (beginOfSuffix > 0) {
//			assert beginOfSuffix < potentialCiphertext.length() - 1;
//			return extractCiphertext(potentialCiphertext.substring(0, beginOfSuffix), dirIdBytes);
//		}
//		
//		// no match:
//		return null;
//	}

	/**
	 * Resolves a conflict.
	 *
	 * @param conflictingPath The path to the potentially conflicting file.
	 * @param canonicalPath The path to the original (conflict-free) file.
	 * @param dirId The directory id of the file's parent directory.
	 * @return The new path of the conflicting file after the conflict has been resolved.
	 * @throws IOException
	 */
	private Path resolveConflict(Path conflictingPath, Path canonicalPath, String dirId) throws IOException {
		if (resolveConflictTrivially(canonicalPath, conflictingPath)) {
			return canonicalPath;
		}
		
		// get ciphertext part from file:
		String canonicalFileName = canonicalPath.getFileName().toString();
		String ciphertext;
		if (longFileNameProvider.isDeflated(canonicalFileName)) {
			String inflatedFileName = longFileNameProvider.inflate(canonicalPath);
			ciphertext = StringUtils.removeEnd(inflatedFileName, CRYPTOMATOR_FILE_SUFFIX);
		} else {
			ciphertext = StringUtils.removeEnd(canonicalFileName, CRYPTOMATOR_FILE_SUFFIX);
		}

		return renameConflictingFile(canonicalPath, conflictingPath, ciphertext, dirId);
	}

	/**
	 * Resolves a conflict by renaming the conflicting file.
	 * 
	 * @param canonicalPath The path to the original (conflict-free) file.
	 * @param conflictingPath The path to the potentially conflicting file.
	 * @param ciphertext The (previously inflated) ciphertext name of the file without any preceeding directory prefix.
	 * @param dirId The directory id of the file's parent directory.
	 * @return The new path after renaming the conflicting file.
	 * @throws IOException
	 */
	private Path renameConflictingFile(Path canonicalPath, Path conflictingPath, String ciphertext, String dirId) throws IOException {
		assert Files.exists(canonicalPath);
		Path ciphertextParentDir = canonicalPath.getParent();
		try {
			String cleartext = cryptor.fileNameCryptor().decryptFilename(BaseEncoding.base64Url(), ciphertext, dirId.getBytes(StandardCharsets.UTF_8));
			CiphertextFilePath alternativePath;
			int i = 1;
			do {
				String alternativeCleartext = cleartext + " (Conflict " + i++ + ")";
				alternativePath = cryptoPathMapper.getCiphertextFilePath(ciphertextParentDir, dirId, alternativeCleartext);
			} while(Files.exists(alternativePath.getRawPath()));
			LOG.info("Moving conflicting file {} to {}", conflictingPath, alternativePath.getRawPath());
			Path resolved = Files.move(conflictingPath, alternativePath.getRawPath(), StandardCopyOption.ATOMIC_MOVE);
			alternativePath.persistLongFileName();
			return resolved;
		} catch (AuthenticationFailedException e) {
			// not decryptable, no need to resolve any kind of conflict
			LOG.info("Found valid Base64 string, which is an unauthentic ciphertext: {}", conflictingPath);
			return conflictingPath;
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
		} else if (hasSameFileContent(conflictingPath.resolve(DIR_FILE_NAME), canonicalPath.resolve(DIR_FILE_NAME), MAX_DIR_FILE_SIZE)) {
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
	 * @return <code>true</code> if the first {@value #MAX_DIR_FILE_SIZE} bytes are equal in both files.
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
