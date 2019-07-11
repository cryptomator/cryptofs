package org.cryptomator.cryptofs;

import com.google.common.io.BaseEncoding;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class to for generating a suffix for the backup file to link it to its original master key file.
 */
public class BackupUtil {

	/**
	 * Computes the SHA-256 digest of the given byte array and returns the first 4 bytes in Hex-String format.
	 *
	 * @param fileBytes the input byte for which the digest is computed.
	 * @return First 4 bytes of SHA-256 digest in Hex-String-Format
	 */
	public static String generateFileId(byte[] fileBytes) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(fileBytes);
			return BaseEncoding.base16().encode(digest, 0, 4);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Every Java Platform must support the Message Digest algorithm SHA-256", e);
		}
	}
}
