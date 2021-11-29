package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

@CryptoFileSystemScoped
public class DirectoryIdBackup {

	@Inject
	Cryptor cryptor;

	public void execute(CryptoPathMapper.CiphertextDirectory ciphertextDirectory) throws IOException {
		try (var channel = Files.newByteChannel(ciphertextDirectory.path.resolve(Constants.DIR_ID_FILE), StandardOpenOption.CREATE_NEW); //
			 var encryptingChannel = new EncryptingWritableByteChannel(channel, cryptor);) {
			encryptingChannel.write(ByteBuffer.wrap(ciphertextDirectory.dirId.getBytes(StandardCharsets.UTF_8)));
		}
	}
}
