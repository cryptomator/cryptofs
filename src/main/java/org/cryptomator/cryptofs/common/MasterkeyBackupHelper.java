package org.cryptomator.cryptofs.common;

import com.google.common.io.BaseEncoding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for generating a suffix for the backup file to make it unique to its original master key file.
 */
public final class MasterkeyBackupHelper {

	private static final Logger LOG = LoggerFactory.getLogger(MasterkeyBackupHelper.class);

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
	 * Do a best-effort attempt to backup the masterkey at the given path. Fail silently if a valid backup already exists.
	 *
	 * @param masterKeyPath The masterkey file to backup
	 * @throws IOException Any non-recoverable I/O exception that occurs during this attempt
	 */
	public static Path attemptMasterKeyBackup(Path masterKeyPath) throws IOException {
		byte[] keyFileContents = Files.readAllBytes(masterKeyPath);
		String backupFileName = masterKeyPath.getFileName().toString() + generateFileIdSuffix(keyFileContents) + Constants.MASTERKEY_BACKUP_SUFFIX;
		Path backupFilePath = masterKeyPath.resolveSibling(backupFileName);
		try (WritableByteChannel ch = Files.newByteChannel(backupFilePath, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
			ch.write(ByteBuffer.wrap(keyFileContents));
		} catch (AccessDeniedException | FileAlreadyExistsException e) {
			assertExistingBackupMatchesContent(backupFilePath, ByteBuffer.wrap(keyFileContents));
		} catch (IOException e) {
			LOG.warn("Failed to backup valid masterkey file.");
		}
		return backupFilePath;
	}

	private static void assertExistingBackupMatchesContent(Path backupFilePath, ByteBuffer expectedContent) {
		if (Files.exists(backupFilePath)) {
			// TODO replace by Files.mismatch() when using JDK > 12
			ByteBuffer buf = ByteBuffer.allocateDirect(expectedContent.remaining() + 1);
			try (ReadableByteChannel ch = Files.newByteChannel(backupFilePath, StandardOpenOption.READ)) {
				ch.read(buf);
				buf.flip();
				if (buf.compareTo(expectedContent) != 0) {
					LOG.warn("Corrupt masterkey backup {}. Please replace it manually or unlock the vault on a writable storage device.", backupFilePath);
				} else {
					LOG.debug("Verified backup file: {}", backupFilePath);
				}
			} catch (IOException e) {
				LOG.warn("Failed to compare valid masterkey with backup file.", e);
			}
		}
	}

}
