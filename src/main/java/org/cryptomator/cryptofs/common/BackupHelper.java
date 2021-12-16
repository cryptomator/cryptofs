package org.cryptomator.cryptofs.common;

import com.google.common.io.BaseEncoding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for generating a suffix for the backup file to make it unique to its original file.
 */
public final class BackupHelper {

	private final static long NO_MISMATCH = -1L;
	private static final Logger LOG = LoggerFactory.getLogger(BackupHelper.class);

	/**
	 * Computes the SHA-256 digest of the given byte array and returns a file suffix containing the first 4 bytes in hex string format.
	 *
	 * @param fileBytes the input byte for which the digest is computed
	 * @return "." + first 4 bytes of SHA-256 digest in hex string format
	 */
	public static String generateFileIdSuffix(byte[] fileBytes) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(fileBytes);
			return "." + BaseEncoding.base16().encode(digest, 0, 4);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Every Java Platform must support the Message Digest algorithm SHA-256", e);
		}
	}

	/**
	 * Do a best-effort attempt to back up the file at the given path.
	 * Fails silently if a _valid_ backup already exists and fails with a log entry, if any IO error occurs while creating or reading the backup file.
	 *
	 * @param path The file to back up
	 * @throws IOException If the path cannot be read.
	 */
	public static Path attemptBackup(Path path) throws IOException {
		byte[] fileContents = Files.readAllBytes(path);
		final String fileToBackup = path.getFileName().toString();
		String backupFileName = fileToBackup + generateFileIdSuffix(fileContents) + Constants.BACKUP_SUFFIX;
		Path backupFilePath = path.resolveSibling(backupFileName);
		try (WritableByteChannel ch = Files.newByteChannel(backupFilePath, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
			ch.write(ByteBuffer.wrap(fileContents));
		} catch (AccessDeniedException | FileAlreadyExistsException e) {
			assertSameContent(backupFilePath, path);
		} catch (IOException e) {
			LOG.warn("Failed to backup valid {} file.", fileToBackup);
		}
		return backupFilePath;
	}

	private static void assertSameContent(final Path backupFile, final Path originalFile) {
		try {
			if (Files.mismatch(backupFile, originalFile) == NO_MISMATCH) {
				LOG.debug("Verified backup file: {}", backupFile);
			} else {
				LOG.warn("Corrupt {} backup for: {}. Please replace it manually or unlock the vault on a writable storage device.", backupFile.getFileName(), backupFile);
			}
		} catch (IOException e) {
			LOG.warn("Failed to compare valid %s with backup file.".formatted(backupFile), e);
		}
	}
}
