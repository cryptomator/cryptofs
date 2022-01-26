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
import java.nio.file.StandardOpenOption;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Single purpose class to backup the directory id of an encrypted directory when it is created.
 */
@CryptoFileSystemScoped
public class DirectoryIdBackup {

	//visible and existing for testing
	private Cryptor cryptor;

	@Inject
	public DirectoryIdBackup(Cryptor cryptor) {
		this.cryptor = cryptor;
	}

	/**
	 * Performs the backup operation for the given {@link CryptoPathMapper.CiphertextDirectory} object.
	 * <p>
	 * The directory id is written via an encrypting channel to the file {@link CryptoPathMapper.CiphertextDirectory#path}/{@value Constants#DIR_ID_FILE}.
	 *
	 * @param ciphertextDirectory The cipher dir object containing the dir id and the encrypted content root
	 * @throws IOException if an IOException is raised during the write operation
	 */
	public void execute(CryptoPathMapper.CiphertextDirectory ciphertextDirectory) throws IOException {
		try (var channel = Files.newByteChannel(ciphertextDirectory.path.resolve(Constants.DIR_ID_FILE), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); //
			 var encryptingChannel = wrapEncryptionAround(channel,cryptor)) {
			encryptingChannel.write(ByteBuffer.wrap(ciphertextDirectory.dirId.getBytes(StandardCharsets.UTF_8)));
		}
	}

	static EncryptingWritableByteChannel wrapEncryptionAround(ByteChannel channel, Cryptor cryptor) {
		return new EncryptingWritableByteChannel(channel, cryptor);
	}
}
