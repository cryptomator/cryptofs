package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.Constants.DIR_PREFIX;
import static org.cryptomator.cryptofs.Constants.NAME_SHORTENING_THRESHOLD;
import static org.cryptomator.cryptofs.LongFileNameProvider.LONG_NAME_FILE_EXT;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.apache.commons.lang3.StringUtils;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@PerFileSystem
class ConflictResolver {

	private static final Logger LOG = LoggerFactory.getLogger(ConflictResolver.class);
	private static final Pattern BASE32_PATTERN = Pattern.compile("0?(([A-Z2-7]{8})*[A-Z2-7=]{8})");
	private static final int MAX_DIR_FILE_SIZE = 87; // "normal" file header has 88 bytes
	private static final int UUID_FIRST_GROUP_STRLEN = 8;

	private final LongFileNameProvider longFileNameProvider;
	private final Cryptor cryptor;

	@Inject
	public ConflictResolver(LongFileNameProvider longFileNameProvider, Cryptor cryptor) {
		this.longFileNameProvider = longFileNameProvider;
		this.cryptor = cryptor;
	}

	public Path resolveConflicts(Path ciphertextPath, String dirId) throws IOException {
		String ciphertextFileName = ciphertextPath.getFileName().toString();
		String resolvedCiphertextFileName = resolveNameConflictIfNecessary(ciphertextPath.getParent(), ciphertextFileName, dirId);
		return ciphertextPath.resolveSibling(resolvedCiphertextFileName);
	}

	private String resolveNameConflictIfNecessary(Path directory, String ciphertextFileName, String dirId) throws IOException {
		String basename = StringUtils.removeEnd(ciphertextFileName, LONG_NAME_FILE_EXT);
		Matcher m = BASE32_PATTERN.matcher(basename);
		if (!m.matches() && m.find(0)) {
			// no full match, but still contains base32 -> partial match
			return resolveConflict(directory, ciphertextFileName, m.group(1), dirId);
		} else {
			// full match or no match at all -> nothing to resolve
			return ciphertextFileName;
		}
	}

	private String resolveConflict(Path directory, String originalFileName, String base32match, String dirId) throws IOException {
		final Path conflictingPath = directory.resolve(originalFileName);
		final String ciphertext;
		final boolean isDirectory;
		final String dirPrefix;
		final Path canonicalPath;
		if (LongFileNameProvider.isDeflated(originalFileName)) {
			String inflated = longFileNameProvider.inflate(base32match + LONG_NAME_FILE_EXT);
			ciphertext = StringUtils.removeStart(inflated, DIR_PREFIX);
			isDirectory = inflated.startsWith(DIR_PREFIX);
			dirPrefix = isDirectory ? DIR_PREFIX : "";
			canonicalPath = directory.resolve(base32match + LONG_NAME_FILE_EXT);
		} else {
			ciphertext = base32match;
			isDirectory = originalFileName.startsWith(DIR_PREFIX);
			dirPrefix = isDirectory ? DIR_PREFIX : "";
			canonicalPath = directory.resolve(dirPrefix + ciphertext);
		}

		/*
		 * Directory files must not result in symlink, make sure the conflicting file is not identical to the original.
		 */
		if (isDirectory && !Files.exists(canonicalPath)) {
			// original file is, so this is no real conflict.
			Files.move(conflictingPath, canonicalPath, StandardCopyOption.ATOMIC_MOVE);
			return canonicalPath.getFileName().toString();
		} else if (isDirectory && hasSameDirFileContent(conflictingPath, canonicalPath)) {
			// there must not be two directories pointing to the same dirId. In this case no human interaction is needed to resolve this conflict:
			LOG.info("Removing conflicting directory file {} (identical to {})", conflictingPath, canonicalPath);
			Files.deleteIfExists(conflictingPath);
			return canonicalPath.getFileName().toString();
		}

		/*
		 * Find alternative name for conflicting file:
		 */
		try {
			String cleartext = cryptor.fileNameCryptor().decryptFilename(ciphertext, dirId.getBytes(StandardCharsets.UTF_8));
			Path alternativePath = canonicalPath;
			while (Files.exists(alternativePath)) {
				String alternativeCleartext = cleartext + " (Conflict " + createConflictId() + ")";
				String alternativeCiphertext = cryptor.fileNameCryptor().encryptFilename(alternativeCleartext, dirId.getBytes(StandardCharsets.UTF_8));
				String alternativeCiphertextFileName = dirPrefix + alternativeCiphertext;
				if (alternativeCiphertextFileName.length() >= NAME_SHORTENING_THRESHOLD) {
					alternativeCiphertextFileName = longFileNameProvider.deflate(alternativeCiphertextFileName);
				}
				alternativePath = directory.resolve(alternativeCiphertextFileName);
			}
			LOG.info("Moving conflicting file {} to {}", conflictingPath, alternativePath);
			Files.move(conflictingPath, alternativePath, StandardCopyOption.ATOMIC_MOVE);
			return alternativePath.getFileName().toString();
		} catch (AuthenticationFailedException e) {
			// not decryptable, no need to resolve any kind of conflict
			LOG.info("Found valid Base32 string, which is an invalid ciphertext: {}", originalFileName);
			return originalFileName;
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
			in1.read(buf1);
			in2.read(buf2);
			buf1.flip();
			buf2.flip();
			return buf1.compareTo(buf2) == 0;
		}
	}

	private static String createConflictId() {
		return UUID.randomUUID().toString().substring(0, UUID_FIRST_GROUP_STRLEN);
	}

}
