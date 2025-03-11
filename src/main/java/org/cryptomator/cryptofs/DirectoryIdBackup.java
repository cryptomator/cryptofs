package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;

import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Single purpose class to read or write the directory id backup of an encrypted directory.
 */
@CryptoFileSystemScoped
public class DirectoryIdBackup {

	private final Cryptor cryptor;

	@Inject
	public DirectoryIdBackup(Cryptor cryptor) {
		this.cryptor = cryptor;
	}

	/**
	 * Writes the dirId backup file for the {@link CiphertextDirectory} object.
	 * <p>
	 * The directory id is written via an encrypting channel to the file {@link CiphertextDirectory#path()}.resolve({@value Constants#DIR_ID_BACKUP_FILE_NAME});
	 *
	 * @param ciphertextDirectory The cipher dir object containing the dir id and the encrypted content root
	 * @throws IOException if an IOException is raised during the write operation
	 */
	public void write(CiphertextDirectory ciphertextDirectory) throws IOException {
		try (var channel = Files.newByteChannel(getBackupFilePath(ciphertextDirectory.path()), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); //
			 var encryptingChannel = wrapEncryptionAround(channel, cryptor)) {
			encryptingChannel.write(ByteBuffer.wrap(ciphertextDirectory.dirId().getBytes(StandardCharsets.US_ASCII)));
		}
	}

	/**
	 * Static method to explicitly back up the directory id for a specified ciphertext directory.
	 *
	 * @param cryptor The cryptor to be used for encryption
	 * @param ciphertextDirectory A {@link CiphertextDirectory} for which the dirId should be back up'd.
	 * @throws IOException when the dirId file already exists, or it cannot be written to.
	 */
	public static void write(Cryptor cryptor, CiphertextDirectory ciphertextDirectory) throws IOException {
		new DirectoryIdBackup(cryptor).write(ciphertextDirectory);
	}


	/**
	 * Reads the dirId backup file and retrieves the directory id from it.
	 *
	 * @param ciphertextContentDir path of a ciphertext <strong>content</strong> directory
	 * @return a byte array containing the directory id
	 * @throws IOException if the dirId backup file cannot be read
	 * @throws CryptoException if the content of dirId backup file cannot be decrypted/authenticated
	 * @throws IllegalStateException if the directory id exceeds {@value Constants#MAX_DIR_ID_LENGTH} chars
	 */
	public byte[] read(Path ciphertextContentDir) throws IOException, CryptoException, IllegalStateException {
		var dirIdBackupFile = getBackupFilePath(ciphertextContentDir);
		var dirIdBuffer = ByteBuffer.allocate(Constants.MAX_DIR_ID_LENGTH + 1); //a dir id contains at most 36 ascii chars, we add for security checks one more

		try (var channel = Files.newByteChannel(dirIdBackupFile, StandardOpenOption.READ); //
			 var decryptingChannel = wrapDecryptionAround(channel, cryptor)) {
			int read = decryptingChannel.read(dirIdBuffer);
			if (read < 0 || read > Constants.MAX_DIR_ID_LENGTH) {
				throw new IllegalStateException("Read directory id exceeds the maximum length of %d characters".formatted(Constants.MAX_DIR_ID_LENGTH));
			}
		}

		var dirId = new byte[dirIdBuffer.position()];
		dirIdBuffer.get(0, dirId);
		return dirId;
	}

	/**
	 * Static method to explicitly retrieve the directory id of a ciphertext directory from the dirId backup file
	 *
	 * @param cryptor The cryptor to be used for decryption
	 * @param ciphertextContentDir path of a ciphertext <strong>content</strong> directory
	 * @return a byte array containing the directory id
	 * @throws IOException if the dirId backup file cannot be read
	 * @throws CryptoException if the content of dirId backup file cannot be decrypted/authenticated
	 * @throws IllegalStateException if the directory id exceeds {@value Constants#MAX_DIR_ID_LENGTH} chars
	 */
	public static byte[] read(Cryptor cryptor, Path ciphertextContentDir) throws IOException, CryptoException, IllegalStateException {
		return new DirectoryIdBackup(cryptor).read(ciphertextContentDir);
	}


	private static Path getBackupFilePath(Path ciphertextContentDir) {
		return ciphertextContentDir.resolve(Constants.DIR_ID_BACKUP_FILE_NAME);
	}

	DecryptingReadableByteChannel wrapDecryptionAround(ByteChannel channel, Cryptor cryptor) {
		return new DecryptingReadableByteChannel(channel, cryptor, true);
	}

	EncryptingWritableByteChannel wrapEncryptionAround(ByteChannel channel, Cryptor cryptor) {
		return new EncryptingWritableByteChannel(channel, cryptor);
	}
}
