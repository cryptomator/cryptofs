package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;

import javax.inject.Inject;
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


	static EncryptingWritableByteChannel wrapEncryptionAround(ByteChannel channel, Cryptor cryptor) {
		return new EncryptingWritableByteChannel(channel, cryptor);
	}
}
